# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Changed in 2023 by Frederique Retsema to create new accounts with a different name,
# based on a prefix that is in the environment variables. 
#
# Most of this is copied from the multi user MySQL Lambda function in the AWS repo
# https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas
#
# I removed the the complexity for RDS instances (n/a for my use case)
#
# The total length of the new username should not exceed 32 characters (newer versions can use longer user names: 
# https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/issues/110 , this Lambda function is used in
# combination with another Lambda function that decides the newest database version that is available).
#
# This Lambda function needs the following environment variables:
#
# SECRETS_MANAGER_ENDPOINT = endpoint for secretsmanager, should be secretsmanager.${AWS::Region}.amazonaws.com, mandatory
# EXCLUDE_CHARACTERS = characters that are excluded, defaults to '/@"\'\\'
# PREFIX = prefix for the usernames, f.e. webuser, defaults to 'user'
# RANDOM_LENGTH = number of randomized characters, defaults to 5. Randomized characters are all uppercase and all lowercase characters and all numbers.
#
# Example username for default PREFIX with default RANDOM_LENGTH: user-xg6Tx.
#
# This Lambda assumes the same fields in the secret as MySQL alternating users secrets (see also:
# https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_available-rotation-templates.html )
# 
# {
#    "engine": "mysql",
#    "host":  "<instance host name/resolvable DNS name>",
#    "username": "<username>",
#    "password": "<password>",
#    "dbname": "<database name. If not specified, defaults to None>",
#    "port": "<TCP port number, if not specified, defaults to 3306>"
#    "masterarn": "arn of a secret of a database user that has CRUD permissions on the database"
# }

import logging
import os
import json
import string
import random

import pymysql
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Secrets Manager Rotation Template

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

    """
    
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ValueError: If the current secret is not valid JSON

        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException: 

        # Get environment variables or use defaults
        exclude_characters = os.environ['EXCLUDE_CHARACTERS'] if 'EXCLUDE_CHARACTERS' in os.environ else '/@"\'\\'
        prefix = os.environ['PREFIX'] if 'PREFIX' in os.environ else 'user'
        random_length = int(os.environ['RANDOM_LENGTH'] if 'RANDOM_LENGTH' in os.environ else '5')

        # Generate a random username and a random password
        pending_dict = current_dict

        new_username = prefix + "-" + get_random_string(random_length)
        new_random_password = service_client.get_random_password(ExcludeCharacters=exclude_characters)
        new_password = new_random_password["RandomPassword"]

        if len(new_username) > 32:
            raise ValueError("Unable to create new user, username length of %s exceeds 32 characters" % (new_username))

        pending_dict['username'] = new_username
        pending_dict['password'] = new_password

        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(pending_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s (new username = %s)." % (arn, token, new_username))


def set_secret(service_client, arn, token):
    """Set the pending secret in the database

    This method tries to login to the database with the AWSPENDING secret and returns on success. If that fails, it
    tries to login with the master credentials from the masterarn in the current secret. If this succeeds, it adds all
    grants for AWSCURRENT user to the AWSPENDING user, creating the user in the process.
    Else, it throws a ValueError.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or master credentials could not be used to login to DB

        KeyError: If the secret json does not contain the expected keys

    """
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)

    # First try to login with the pending secret, if it succeeds, return
    conn = get_connection(pending_dict)
    if conn:
        conn.close()
        logger.info("setSecret: AWSPENDING secret is already set as password in MySQL DB for secret arn %s." % arn)
        return

    # Make sure the host from current and pending match
    if current_dict['host'] != pending_dict['host']:
        logger.error("setSecret: Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))
        raise ValueError("Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))

    # Before we do anything with the secret, make sure the AWSCURRENT secret is valid by logging in to the db
    # This ensures that the credential we are rotating is valid to protect against a confused deputy attack
    conn = get_connection(current_dict)
    if not conn:
        logger.error("setSecret: Unable to log into database using current credentials for secret %s" % arn)
        raise ValueError("Unable to log into database using current credentials for secret %s" % arn)
    conn.close()

    # Use the master arn from the current secret to fetch master secret contents
    master_arn = current_dict['masterarn']
    master_dict = get_secret_dict(service_client, master_arn, "AWSCURRENT", None, True)

    if current_dict['host'] != master_dict['host']:
        logger.error("setSecret: Current database host %s is not the same host as/rds replica of master %s" % (current_dict['host'], master_dict['host']))
        raise ValueError("Current database host %s is not the same host as/rds replica of master %s" % (current_dict['host'], master_dict['host']))

    # Log into the database with the master credentials
    conn = get_connection(master_dict)
    if not conn:
        logger.error("setSecret: Unable to log into database using credentials in master secret %s" % master_arn)
        raise ValueError("Unable to log into database using credentials in master secret %s" % master_arn)

    # Set the password to the pending password
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT User FROM mysql.user WHERE User = %s", pending_dict['username'])
            # Create the user if it does not exist
            if cur.rowcount == 0:
                cur.execute("CREATE USER %s IDENTIFIED BY %s", (pending_dict['username'], pending_dict['password']))

            # Copy grants to the new user
            cur.execute("SHOW GRANTS FOR %s", current_dict['username'])
            role_name = ""
            for row in cur.fetchall():
                grant = row[0].split(' TO ')
                new_grant_escaped = grant[0].replace('%', '%%')  # % is a special character in Python format strings.
                cur.execute(new_grant_escaped + " TO %s", pending_dict['username'])

                is_role = True
                for statement in ["USAGE", "SELECT", "INSERT", "UPDATE", "DELETE"]:
                    if statement in new_grant_escaped:
                        is_role = False
                        break

                if is_role:
                    role_name = row[0].split("`")[1].split("`")[0]
    
            # Set the default to the last role in the list
            if role_name != "":
                cur.execute("SET DEFAULT ROLE %s TO %s", (role_name, pending_dict['username']))

            # Get the version of MySQL
            cur.execute("SELECT VERSION()")
            ver = cur.fetchone()[0]

            # Copy TLS options to the new user
            escaped_encryption_statement = get_escaped_encryption_statement(ver)
            cur.execute("SELECT ssl_type, ssl_cipher, x509_issuer, x509_subject FROM mysql.user WHERE User = %s", current_dict['username'])
            tls_options = cur.fetchone()
            ssl_type = tls_options[0]
            if not ssl_type:
                cur.execute(escaped_encryption_statement + " NONE", pending_dict['username'])
                logger.info("setSecret: ssl_type: NONE")
            elif ssl_type == "ANY":
                cur.execute(escaped_encryption_statement + " SSL", pending_dict['username'])
                logger.info("setSecret: ssl_type: SSL")
            elif ssl_type == "X509":
                cur.execute(escaped_encryption_statement + " X509", pending_dict['username'])
                logger.info("setSecret: ssl_type: X509")
            else:
                cur.execute(escaped_encryption_statement + " CIPHER %s AND ISSUER %s AND SUBJECT %s", (pending_dict['username'], tls_options[1], tls_options[2], tls_options[3]))
                logger.info("setSecret: ssl_type: CIPHER, ISSUER, SUBJECT")

            # Set the password for the user and commit
            password_option = get_password_option(ver)
            cur.execute("SET PASSWORD FOR %s = " + password_option, (pending_dict['username'], pending_dict['password']))
            conn.commit()
            logger.info("setSecret: Successfully set password for %s in MySQL DB for secret arn %s." % (pending_dict['username'], arn))
    finally:
        conn.close()


def test_secret(service_client, arn, token):
    """Test the pending secret against the database

    This method tries to log into the database with the secrets staged with AWSPENDING and runs
    a permissions check to ensure the user has the correct permissions.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or pending credentials could not be used to login to the database

        KeyError: If the secret json does not contain the expected keys

    """
    # Try to login with the pending secret, if it succeeds, return
    conn = get_connection(get_secret_dict(service_client, arn, "AWSPENDING", token))
    if conn:
        # This is where the lambda will validate the user's permissions. Modify the below lines to
        # tailor these validations to your needs
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM demodb.prices")
                conn.commit()
        finally:
            conn.close()

        logger.info("testSecret: Successfully signed into MySQL DB with AWSPENDING secret in %s." % arn)
    else:
        logger.error("testSecret: Unable to log into database with pending secret of secret ARN %s" % arn)
        raise ValueError("Unable to log into database with pending secret of secret ARN %s" % arn)


def finish_secret(service_client, arn, token):
    """Finish the rotation by marking the pending secret as current

    This method moves the secret from the AWSPENDING stage to the AWSCURRENT stage.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))

    # Delete old database users
    delete_old_database_users(service_client, arn)


def get_connection(secret_dict):
    """Gets a connection to MySQL DB from a secret dictionary

    This helper function uses connectivity information from the secret dictionary to initiate
    connection attempt(s) to the database. Will attempt a fallback, non-SSL connection when
    initial connection fails using SSL and fall_back is True.

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Connection: The pymysql.connections.Connection object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Parse and validate the secret JSON string
    port = int(secret_dict['port']) if 'port' in secret_dict else 3306
    dbname = secret_dict['dbname'] if 'dbname' in secret_dict else None

    # Get SSL connectivity configuration
    use_ssl, fall_back = get_ssl_config(secret_dict)

    # if an 'ssl' key is not found or does not contain a valid value, attempt an SSL connection and fall back to non-SSL on failure
    conn = connect_and_authenticate(secret_dict, port, dbname, use_ssl)
    if conn or not fall_back:
        return conn
    else:
        return connect_and_authenticate(secret_dict, port, dbname, False)


def get_ssl_config(secret_dict):
    """Gets the desired SSL and fall back behavior using a secret dictionary

    This helper function uses the existance and value the 'ssl' key in a secret dictionary
    to determine desired SSL connectivity configuration. Its behavior is as follows:
        - 'ssl' key DNE or invalid type/value: return True, True
        - 'ssl' key is bool: return secret_dict['ssl'], False
        - 'ssl' key equals "true" ignoring case: return True, False
        - 'ssl' key equals "false" ignoring case: return False, False

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Tuple(use_ssl, fall_back): SSL configuration
            - use_ssl (bool): Flag indicating if an SSL connection should be attempted
            - fall_back (bool): Flag indicating if non-SSL connection should be attempted if SSL connection fails

    """
    # Default to True for SSL and fall_back mode if 'ssl' key DNE
    if 'ssl' not in secret_dict:
        return True, True

    # Handle type bool
    if isinstance(secret_dict['ssl'], bool):
        return secret_dict['ssl'], False

    # Handle type string
    if isinstance(secret_dict['ssl'], str):
        ssl = secret_dict['ssl'].lower()
        if ssl == "true":
            return True, False
        elif ssl == "false":
            return False, False
        else:
            # Invalid string value, default to True for both SSL and fall_back mode
            return True, True

    # Invalid type, default to True for both SSL and fall_back mode
    return True, True


def connect_and_authenticate(secret_dict, port, dbname, use_ssl):
    """Attempt to connect and authenticate to a MySQL instance

    This helper function tries to connect to the database using connectivity info passed in.
    If successful, it returns the connection, else None

    Args:
        - secret_dict (dict): The Secret Dictionary
        - port (int): The databse port to connect to
        - dbname (str): Name of the database
        - use_ssl (bool): Flag indicating whether connection should use SSL/TLS

    Returns:
        Connection: The pymongo.database.Database object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    ssl = {'ca': '/etc/pki/tls/cert.pem'} if use_ssl else None

    # Try to obtain a connection to the db
    try:
        # Checks hostname and verifies server certificate implictly when 'ca' key is in 'ssl' dictionary
        conn = pymysql.connect(host=secret_dict['host'], user=secret_dict['username'], password=secret_dict['password'], port=port, database=dbname, connect_timeout=5, ssl=ssl)
        logger.info("Successfully established %s connection as user '%s' with host: '%s'" % ("SSL/TLS" if use_ssl else "non SSL/TLS", secret_dict['username'], secret_dict['host']))
        return conn
    except pymysql.OperationalError as e:
        if 'certificate verify failed: IP address mismatch' in e.args[1]:
            logger.error("Hostname verification failed when estlablishing SSL/TLS Handshake with host: %s" % secret_dict['host'])
        return None


def get_secret_dict(service_client, arn, stage, token=None, master_secret=False):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        stage (string): The stage identifying the secret version

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        master_secret (boolean): A flag that indicates if we are getting a master secret.

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON

    """
    required_fields = ['host', 'username', 'password', 'engine']

    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    if secret_dict['engine'] != 'mysql':
        raise KeyError("Database engine must be set to 'mysql' in order to use this rotation lambda")

    # Parse and return the secret JSON string
    return secret_dict


def get_password_option(version):
    """Gets the password option template string to use for the SET PASSWORD sql query

    This helper function takes in the mysql version and returns the appropriate password option template string that can
    be used in the SET PASSWORD query for that mysql version.

    Args:
        version (string): The mysql database version

    Returns:
        PasswordOption: The password option string

    """
    if version.startswith("8"):
        return "%s"
    else:
        return "PASSWORD(%s)"


def get_escaped_encryption_statement(version):
    """Gets the SQL statement to require TLS options on a user

    This helper function takes in the mysql version and returns the appropriate escaped SQL statement based on the
    version of MySQL being used.

    Args:
        version (string): The mysql database version

    Returns:
        encryptionStatement (string): SQL statement to require TLS options on a user

    """
    if version.startswith("5.6"):
        return "GRANT USAGE ON *.* TO %s@'%%' REQUIRE"
    else:
        return "ALTER USER %s@'%%' REQUIRE"


def get_random_string(length):
    """Gets a random number of characters, to add to the user name

    This helper function takes in the length of the randomized part of the username and returns the randomozed characters.
    Copied from: https://pynative.com/python-generate-random-string/    

    Args:
        length (int): number of randomized characters to return

    Returns:
        result_str (string): string with randomized characters

    """
    letters = string.ascii_lowercase + string.ascii_uppercase +string.digits
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def delete_old_database_users(service_client, arn):
    """Delete old database users

    This helper function logs in to the database and then removes the old database users, i.e. all users that start
    with the prefix + "-" and are not the AWSCURRENT or AWSPREVIOUS versions of the secret.

    It uses the DROP USER command to remove the users.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

    Returns:
        nothing

    """

    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    previous_dict = get_secret_dict(service_client, arn, "AWSPREVIOUS")
    master_arn = current_dict['masterarn']
    master_dict = get_secret_dict(service_client, master_arn, "AWSCURRENT", None, True)

    prefix = os.environ['PREFIX'] if 'PREFIX' in os.environ else 'user'

    current_username = current_dict["username"]
    previous_username = previous_dict["username"]

    if current_dict['host'] != master_dict['host']:
        logger.error("finishSecret: Current database host %s is not the same host as/rds replica of master %s" % (current_dict['host'], master_dict['host']))
        raise ValueError("Current database host %s is not the same host as/rds replica of master %s" % (current_dict['host'], master_dict['host']))

    # Now log into the database with the master credentials
    conn = get_connection(master_dict)
    if not conn:
        logger.error("finishSecret: Unable to log into database using credentials in master secret %s" % master_arn)
        raise ValueError("Unable to log into database using credentials in master secret %s" % master_arn)

    # Remove users that start with prefix- and are not the current or previous user
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user FROM mysql.user WHERE user LIKE CONCAT(%s, '-', '%%') AND USER NOT IN (%s, %s)", (prefix, current_username, previous_username))
            users = cur.fetchall()

            for user in users:
              logger.info("finishSecret: Drop user %s" % user)
              cur.execute("DROP USER %s", user)

        logger.info("finishSecret: Successfully dropped old users from %s" % arn)
    finally:
        conn.close()
