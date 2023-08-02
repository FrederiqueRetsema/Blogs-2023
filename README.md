# Blogs-2023
This repository contains the files as support for my blogs on the AMIS technology blog ( https://technology.amis.nl ).

# Secretsmanager
Demo how to use the secretsmanager, with automated renewal of the database password.  
Direct link to the blog: https://technology.amis.nl/aws/first-steps-in-rotating-secrets-in-aws-secrets-manager/

I wrote a second blog as well, to show how to use your own Lambda function.

Direct link to this blog: https://technology.amis.nl/aws/writing-your-own-lambda-function-for-secret-rotation/

# LazyLoading in Fargate
See the blog article: https://technology.amis.nl/aws/lazy-loading-with-aws-fargate/

Deployment: for deployment in your own environment you need an S3 bucket (this is because the template is rather big). After you created your S3 bucket, use the following command to deploy the template:

aws cloudformation deploy --template-file .\lazyloadingfargate\LazyLoading.yaml --stack-name LazyLoading --capabilities CAPABILITY_IAM --s3-bucket your-S3-bucket

The templates uses two files, where one of them is too big to upload to git. You can get these files by using curl:
curl -O https://frpublic2.s3.eu-west-1.amazonaws.com/Xforce/Code/mysql_dump.sql 
curl -O https://frpublic2.s3.eu-west-1.amazonaws.com/Xforce/Code/uploads.tar.gz 
