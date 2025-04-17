#!/home/sumar/.local/share/mise/installs/python/3.12.10/bin/python

import argparse
import boto3
import json
import os
import subprocess
import sys
import logging
from typing import Dict, List, Optional, Union

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('secret-manager')

class SecretManager:
    def __init__(self, region_name=None):
        """Initialize the Secret Manager with optional region configuration."""
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        self.client = boto3.client('secretsmanager', region_name=self.region_name)
    
    def get_secret(self, secret_name: str) -> Dict:
        """Retrieve a secret from AWS Secrets Manager."""
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            if 'SecretString' in response:
                return json.loads(response['SecretString'])
            else:
                logger.warning("Secret value is binary. Not supported yet.")
                return {}
        except Exception as e:
            logger.error(f"Error retrieving secret {secret_name}: {str(e)}")
            return {}
    
    def list_secrets(self) -> List[str]:
        """List available secrets in AWS Secrets Manager."""
        try:
            response = self.client.list_secrets()
            return [secret['Name'] for secret in response.get('SecretList', [])]
        except Exception as e:
            logger.error(f"Error listing secrets: {str(e)}")
            return []
    
    def create_secret(self, secret_name: str, secret_value: Union[Dict, str], description: Optional[str] = None) -> bool:
        """Create a new secret in AWS Secrets Manager."""
        try:
            # Convert dict to JSON string if needed
            if isinstance(secret_value, dict):
                secret_string = json.dumps(secret_value)
            else:
                secret_string = secret_value
                
            kwargs = {
                'Name': secret_name,
                'SecretString': secret_string
            }
            
            if description:
                kwargs['Description'] = description
                
            self.client.create_secret(**kwargs)
            logger.info(f"Secret {secret_name} created successfully")
            return True
        except Exception as e:
            logger.error(f"Error creating secret {secret_name}: {str(e)}")
            return False
    
    def update_secret(self, secret_name: str, secret_value: Union[Dict, str]) -> bool:
        """Update an existing secret in AWS Secrets Manager."""
        try:
            # Convert dict to JSON string if needed
            if isinstance(secret_value, dict):
                secret_string = json.dumps(secret_value)
            else:
                secret_string = secret_value
                
            self.client.update_secret(
                SecretId=secret_name,
                SecretString=secret_string
            )
            logger.info(f"Secret {secret_name} updated successfully")
            return True
        except Exception as e:
            logger.error(f"Error updating secret {secret_name}: {str(e)}")
            return False
    
    def delete_secret(self, secret_name: str, force_delete: bool = False) -> bool:
        """Delete a secret from AWS Secrets Manager."""
        try:
            # By default, AWS adds a recovery window
            # force_delete=True will bypass the recovery window
            kwargs = {
                'SecretId': secret_name
            }
            
            if force_delete:
                kwargs['ForceDeleteWithoutRecovery'] = True
            else:
                # Default recovery window is 30 days
                kwargs['RecoveryWindowInDays'] = 30
                
            self.client.delete_secret(**kwargs)
            
            if force_delete:
                logger.info(f"Secret {secret_name} deleted permanently")
            else:
                logger.info(f"Secret {secret_name} scheduled for deletion (30-day recovery period)")
            return True
        except Exception as e:
            logger.error(f"Error deleting secret {secret_name}: {str(e)}")
            return False

def run_command(args: List[str], env_vars: Dict[str, str]) -> int:
    """Run a command with the provided environment variables."""
    merged_env = {**os.environ, **env_vars}
    try:
        logger.info(f"Running command: {' '.join(args)}")
        process = subprocess.Popen(args, env=merged_env)
        return process.wait()
    except Exception as e:
        logger.error(f"Error running command: {str(e)}")
        return 1

def parse_key_value_pair(pair: str) -> tuple:
    """Parse a key-value pair in the format key=value."""
    if '=' not in pair:
        raise ValueError(f"Invalid format: {pair}. Expected format: key=value")
    
    key, value = pair.split('=', 1)
    return key.strip(), value.strip()

def main():
    parser = argparse.ArgumentParser(description="AWS Secret Management Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run a command with secrets injected as env vars")
    run_parser.add_argument("--secret", "-s", help="Secret name to load", required=True)
    run_parser.add_argument("--prefix", "-p", help="Environment variable prefix", default="")
    run_parser.add_argument("--region", "-r", help="AWS region", default=None)
    run_parser.add_argument("app", help="Application to run")
    run_parser.add_argument("app_args", nargs="*", help="Arguments for the application")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available secrets")
    list_parser.add_argument("--region", "-r", help="AWS region", default=None)
    
    # Get command
    get_parser = subparsers.add_parser("get", help="Get a secret's values")
    get_parser.add_argument("--region", "-r", help="AWS region", default=None)
    get_parser.add_argument("secret_name", help="Name of the secret to retrieve")
    
    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new secret")
    create_parser.add_argument("--region", "-r", help="AWS region", default=None)
    create_parser.add_argument("--description", "-d", help="Secret description", default=None)
    create_parser.add_argument("--file", "-f", help="JSON file with secret values")
    create_parser.add_argument("secret_name", help="Name for the new secret")
    create_parser.add_argument("key_values", nargs="*", help="Key-value pairs in format key=value")
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update an existing secret")
    update_parser.add_argument("--region", "-r", help="AWS region", default=None)
    update_parser.add_argument("--file", "-f", help="JSON file with secret values")
    update_parser.add_argument("secret_name", help="Name of the secret to update")
    update_parser.add_argument("key_values", nargs="*", help="Key-value pairs in format key=value")
    
    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a secret")
    delete_parser.add_argument("--region", "-r", help="AWS region", default=None)
    delete_parser.add_argument("--force", action="store_true", help="Force delete without recovery window")
    delete_parser.add_argument("secret_name", help="Name of the secret to delete")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == "list":
        secret_manager = SecretManager(region_name=args.region)
        secrets = secret_manager.list_secrets()
        print("Available secrets:")
        for secret in secrets:
            print(f"- {secret}")
        return 0
    
    elif args.command == "get":
        secret_manager = SecretManager(region_name=args.region)
        secret_data = secret_manager.get_secret(args.secret_name)
        
        if not secret_data:
            logger.error(f"No secret data found for {args.secret_name}")
            return 1
            
        print(json.dumps(secret_data, indent=2))
        return 0
    
    elif args.command == "create":
        secret_manager = SecretManager(region_name=args.region)
        
        # Check if secret already exists
        if args.secret_name in secret_manager.list_secrets():
            logger.error(f"Secret {args.secret_name} already exists. Use 'update' instead.")
            return 1
            
        # Load secret values
        secret_data = {}
        
        # From file if specified
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    secret_data = json.load(f)
            except Exception as e:
                logger.error(f"Error loading secret file: {str(e)}")
                return 1
        
        # From command line arguments
        for kv in args.key_values:
            try:
                key, value = parse_key_value_pair(kv)
                secret_data[key] = value
            except ValueError as e:
                logger.error(str(e))
                return 1
        
        if not secret_data:
            logger.error("No secret values provided. Use --file or provide key=value pairs.")
            return 1
            
        success = secret_manager.create_secret(args.secret_name, secret_data, args.description)
        return 0 if success else 1
    
    elif args.command == "update":
        secret_manager = SecretManager(region_name=args.region)
        
        # Check if secret exists
        if args.secret_name not in secret_manager.list_secrets():
            logger.error(f"Secret {args.secret_name} does not exist. Use 'create' instead.")
            return 1
        
        # Load current secret values first (for merging)
        current_secret = secret_manager.get_secret(args.secret_name)
        secret_data = current_secret.copy() if current_secret else {}
        
        # From file if specified
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    file_data = json.load(f)
                    # Merge with existing data
                    secret_data.update(file_data)
            except Exception as e:
                logger.error(f"Error loading secret file: {str(e)}")
                return 1
        
        # From command line arguments
        for kv in args.key_values:
            try:
                key, value = parse_key_value_pair(kv)
                secret_data[key] = value
            except ValueError as e:
                logger.error(str(e))
                return 1
        
        if secret_data == current_secret:
            logger.warning("No changes to update.")
            return 0
            
        success = secret_manager.update_secret(args.secret_name, secret_data)
        return 0 if success else 1
    
    elif args.command == "delete":
        secret_manager = SecretManager(region_name=args.region)
        
        # Check if secret exists
        if args.secret_name not in secret_manager.list_secrets():
            logger.error(f"Secret {args.secret_name} does not exist.")
            return 1
        
        success = secret_manager.delete_secret(args.secret_name, args.force)
        return 0 if success else 1
    
    elif args.command == "run":
        secret_manager = SecretManager(region_name=args.region)
        secret_data = secret_manager.get_secret(args.secret)
        
        if not secret_data:
            logger.error(f"No secret data found for {args.secret}")
            return 1
        
        # Prepare environment variables from secrets
        env_vars = {}
        for key, value in secret_data.items():
            env_name = f"{args.prefix}{key}" if args.prefix else key
            env_vars[env_name] = str(value)
        
        # Log the secrets being injected (keys only for security)
        logger.info(f"Injecting secrets: {', '.join(env_vars.keys())}")
        
        # Run the command with the environment variables
        cmd = [args.app] + args.app_args
        return run_command(cmd, env_vars)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())