import json
import boto3
import hashlib
import logging
from botocore.exceptions import ClientError
from datetime import datetime

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize DynamoDB and SES
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Users')  # DynamoDB table name
ses = boto3.client('ses')

# Hashing function for emails
def hash_email(email):
    return hashlib.sha256(email.encode()).hexdigest()

def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))
    
    try:
        # Log raw body to help debug if issues occur
        logger.info(f"Raw event body: {event.get('body', 'No body in event')}")

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
        
        # Extract name, email, Teamname, and Contact from the parsed body
        name = body.get('name')
        email = body.get('email')
        teamnamelam = body.get('teamname')
        contactno = body.get('contact')
        
        # Check if both name and email are provided
        if not name or not email:
            raise ValueError("Name and email must be provided.")
        
        # Hash the email for secure storage in DynamoDB
        hashed_email = hash_email(email)
        
        # Store user information in DynamoDB
        table.put_item(
            Item={
                'name': name,
                'email': email,
                'Teamname': teamnamelam,  # Match the exact field name from frontend
                'Contact': contactno,  # Match the exact field name from frontend
                'registrationTime': datetime.now().isoformat(),  # Store registration time
            },
            ConditionExpression="attribute_not_exists(email)"  # Ensure item is not overwritten
        )
        
        # Send an email using SES from a domain-based address
        response = ses.send_email(
            Source='iNFAMOUS@infamousesports.tech',  # Use a generic address from your verified domain
            Destination={
                'ToAddresses': [email]  # The recipient's email
            },
            Message={
                'Subject': {
                    'Data': 'Tournament Registration Confirmation'
                },
                'Body': {
                    'Text': {
                        'Data': f"Hello {name}, you have successfully registered for the tournament!"
                    }
                }
            }
        )
        
        # Log the response from SES
        logger.info(f"SES response: {response}")
        
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
