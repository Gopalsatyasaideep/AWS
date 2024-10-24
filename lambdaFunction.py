import json
import boto3
import hashlib
import logging
from botocore.exceptions import ClientError
from datetime import datetime

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize DynamoDB and SNS
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Users')  # DynamoDB table name
sns = boto3.client('sns')

# Hashing function for emails
def hash_email(email):
    return hashlib.sha256(email.encode()).hexdigest()

def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))
    
    try:
        # Check if the event contains a 'body' field
        if 'body' in event:
            # Parse the event body, ensure it's in JSON format
            if isinstance(event['body'], str):
                body = json.loads(event['body'])
            else:
                body = event['body']
        else:
            # For direct Lambda invocations where 'body' might not exist
            body = event
        
        # Extract name and email from the parsed body
        name = body.get('name')
        email = body.get('email')
        
        # Check if both name and email are provided
        if not name or not email:
            raise ValueError("Name and email must be provided.")
        
        # Hash the email for secure storage in DynamoDB
        hashed_email = hash_email(email)
        
        # Store user information in DynamoDB
        table.put_item(
            Item={
                'name': name,
                'email': hashed_email,  # Store hashed email
                'registrationTime': datetime.now().isoformat(),  # Store registration time
            },
            ConditionExpression="attribute_not_exists(email)"  # Ensure item is not overwritten
        )
        
        # Subscribe the email to the SNS topic dynamically
        sns_topic_arn = 'arn:aws:sns:us-east-1:008971632822:RegistrationNotifications'  # Replace with your SNS Topic ARN
        sns.subscribe(
            Protocol='email',  # Email protocol for subscription
            TopicArn=sns_topic_arn,
            Endpoint=email  # Subscribe the user's email
        )
        
        # Send a confirmation message to the user via SNS
        sns.publish(
            TopicArn=sns_topic_arn,
            Message=f"Hello {name}, you have successfully registered for the tournament!",
            Subject='Tournament Registration Confirmation'
        )
        
        # Return success response 
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'User registered, data stored, and notification sent successfully!'})
        }
    
    except ClientError as e:
        logger.error(f"ClientError: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error registering user: {str(e)}')
        }
    
    except ValueError as e:
        logger.error(f"ValueError: {str(e)}")
        return {
            'statusCode': 400,
            'body': json.dumps(f'Validation Error: {str(e)}')
        }
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error registering user: {str(e)}')
        }
