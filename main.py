#!/home/sumar/.local/share/mise/installs/python/3.12.10/bin/python

import argparse
import boto3
import json
import os
import subprocess
import sys
import logging
from typing import Dict, List, Optional, Union
from abc import ABC, abstractmethod

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('secret-manager')

class SecretStorageProvider(ABC):
    """Abstract base class for secret storage providers."""
    
    @abstractmethod
    def get_secret(self, secret_name: str) -> Dict:
        """Retrieve a secret from the storage provider."""
        pass
    
    @abstractmethod
    def list_secrets(self) -> List[str]:
        """List available secrets in the storage provider."""
        pass
    
    @abstractmethod
    def create_secret(self, secret_name: str, secret_value: Union[Dict, str], description: Optional[str] = None) -> bool:
        """Create a new secret in the storage provider."""
        pass
    
    @abstractmethod
    def update_secret(self, secret_name: str, secret_value: Union[Dict, str]) -> bool:
        """Update an existing secret in the storage provider."""
        pass
    
    @abstractmethod
    def delete_secret(self, secret_name: str, force_delete: bool = False) -> bool:
        """Delete a secret from the storage provider."""
        pass

class SecretsManagerProvider(SecretStorageProvider):
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

class ParameterStoreProvider(SecretStorageProvider):
    def __init__(self, region_name=None):
        """Initialize the Parameter Store provider with optional region configuration."""
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        self.client = boto3.client('ssm', region_name=self.region_name)
        self.path_prefix = '/secret/'  # Default path prefix for parameters
    
    def get_secret(self, secret_name: str) -> Dict:
        """Retrieve a secret from AWS Parameter Store."""
        try:
            # Ensure the name has the correct prefix
            param_name = self._ensure_path_prefix(secret_name)
            
            response = self.client.get_parameter(
                Name=param_name,
                WithDecryption=True
            )
            
            if 'Parameter' in response and 'Value' in response['Parameter']:
                try:
                    # Try to parse as JSON
                    return json.loads(response['Parameter']['Value'])
                except json.JSONDecodeError:
                    # If not JSON, return as singleton dict
                    return {"value": response['Parameter']['Value']}
            else:
                logger.warning(f"No value found for parameter {param_name}")
                return {}
        except Exception as e:
            logger.error(f"Error retrieving parameter {secret_name}: {str(e)}")
            return {}
    
    def list_secrets(self) -> List[str]:
        """List available secrets in AWS Parameter Store."""
        try:
            # Get parameters by path (recursive)
            response = self.client.get_parameters_by_path(
                Path=self.path_prefix,
                Recursive=True
            )
            
            # Strip the prefix to return just the name part
            return [param['Name'].replace(self.path_prefix, '', 1) for param in response.get('Parameters', [])]
        except Exception as e:
            logger.error(f"Error listing parameters: {str(e)}")
            return []
    
    def create_secret(self, secret_name: str, secret_value: Union[Dict, str], description: Optional[str] = None) -> bool:
        """Create a new secret in AWS Parameter Store."""
        try:
            # Ensure the name has the correct prefix
            param_name = self._ensure_path_prefix(secret_name)
            
            # Convert dict to JSON string if needed
            if isinstance(secret_value, dict):
                value = json.dumps(secret_value)
            else:
                value = secret_value
                
            kwargs = {
                'Name': param_name,
                'Value': value,
                'Type': 'SecureString',
                'Overwrite': False
            }
            
            if description:
                kwargs['Description'] = description
                
            self.client.put_parameter(**kwargs)
            logger.info(f"Parameter {secret_name} created successfully")
            return True
        except Exception as e:
            logger.error(f"Error creating parameter {secret_name}: {str(e)}")
            return False
    
    def update_secret(self, secret_name: str, secret_value: Union[Dict, str]) -> bool:
        """Update an existing secret in AWS Parameter Store."""
        try:
            # Ensure the name has the correct prefix
            param_name = self._ensure_path_prefix(secret_name)
            
            # Convert dict to JSON string if needed
            if isinstance(secret_value, dict):
                value = json.dumps(secret_value)
            else:
                value = secret_value
                
            self.client.put_parameter(
                Name=param_name,
                Value=value,
                Type='SecureString',
                Overwrite=True
            )
            logger.info(f"Parameter {secret_name} updated successfully")
            return True
        except Exception as e:
            logger.error(f"Error updating parameter {secret_name}: {str(e)}")
            return False
    
    def delete_secret(self, secret_name: str, force_delete: bool = False) -> bool:
        """Delete a secret from AWS Parameter Store."""
        try:
            # Ensure the name has the correct prefix
            param_name = self._ensure_path_prefix(secret_name)
            
            self.client.delete_parameter(Name=param_name)
            logger.info(f"Parameter {secret_name} deleted successfully")
            return True
        except Exception as e:
            logger.error(f"Error deleting parameter {secret_name}: {str(e)}")
            return False
    
    def _ensure_path_prefix(self, name: str) -> str:
        """Ensure the parameter name has the proper path prefix."""
        if name.startswith(self.path_prefix):
            return name
        return f"{self.path_prefix}{name}"

class SecretManager:
    def __init__(self, provider_type='secretsmanager', region_name=None):
        """Initialize the Secret Manager with selected provider."""
        if provider_type == 'parameterstore':
            self.provider = ParameterStoreProvider(region_name)
            logger.info("Using Parameter Store provider (cost-effective option)")
        else:  # Default to secrets manager
            self.provider = SecretsManagerProvider(region_name)
            logger.info("Using Secrets Manager provider")
    
    def get_secret(self, secret_name: str) -> Dict:
        """Retrieve a secret from the configured provider."""
        return self.provider.get_secret(secret_name)
    
    def list_secrets(self) -> List[str]:
        """List available secrets in the configured provider."""
        return self.provider.list_secrets()
    
    def create_secret(self, secret_name: str, secret_value: Union[Dict, str], description: Optional[str] = None) -> bool:
        """Create a new secret in the configured provider."""
        return self.provider.create_secret(secret_name, secret_value, description)
    
    def update_secret(self, secret_name: str, secret_value: Union[Dict, str]) -> bool:
        """Update an existing secret in the configured provider."""
        return self.provider.update_secret(secret_name, secret_value)
    
    def delete_secret(self, secret_name: str, force_delete: bool = False) -> bool:
        """Delete a secret from the configured provider."""
        return self.provider.delete_secret(secret_name, force_delete)

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
    run_parser.add_argument("--provider", "-P", choices=['secretsmanager', 'parameterstore'], 
                        default='secretsmanager',
                        help="Secret storage provider (secretsmanager is default, parameterstore is more cost-effective)")
    run_parser.add_argument("app", help="Application to run")
    run_parser.add_argument("app_args", nargs="*", help="Arguments for the application")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available secrets")
    list_parser.add_argument("--region", "-r", help="AWS region", default=None)
    list_parser.add_argument("--provider", "-P", choices=['secretsmanager', 'parameterstore'], 
                        default='secretsmanager',
                        help="Secret storage provider (secretsmanager is default, parameterstore is more cost-effective)")
    
    # Get command
    get_parser = subparsers.add_parser("get", help="Get a secret's values")
    get_parser.add_argument("--region", "-r", help="AWS region", default=None)
    get_parser.add_argument("--provider", "-P", choices=['secretsmanager', 'parameterstore'], 
                        default='secretsmanager',
                        help="Secret storage provider (secretsmanager is default, parameterstore is more cost-effective)")
    get_parser.add_argument("secret_name", help="Name of the secret to retrieve")
    
    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new secret")
    create_parser.add_argument("--region", "-r", help="AWS region", default=None)
    create_parser.add_argument("--provider", "-P", choices=['secretsmanager', 'parameterstore'], 
                        default='secretsmanager',
                        help="Secret storage provider (secretsmanager is default, parameterstore is more cost-effective)")
    create_parser.add_argument("--description", "-d", help="Secret description", default=None)
    create_parser.add_argument("--file", "-f", help="JSON file with secret values")
    create_parser.add_argument("secret_name", help="Name for the new secret")
    create_parser.add_argument("key_values", nargs="*", help="Key-value pairs in format key=value")
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update an existing secret")
    update_parser.add_argument("--region", "-r", help="AWS region", default=None)
    update_parser.add_argument("--provider", "-P", choices=['secretsmanager', 'parameterstore'], 
                        default='secretsmanager',
                        help="Secret storage provider (secretsmanager is default, parameterstore is more cost-effective)")
    update_parser.add_argument("--file", "-f", help="JSON file with secret values")
    update_parser.add_argument("secret_name", help="Name of the secret to update")
    update_parser.add_argument("key_values", nargs="*", help="Key-value pairs in format key=value")
    
    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a secret")
    delete_parser.add_argument("--region", "-r", help="AWS region", default=None)
    delete_parser.add_argument("--provider", "-P", choices=['secretsmanager', 'parameterstore'], 
                        default='secretsmanager',
                        help="Secret storage provider (secretsmanager is default, parameterstore is more cost-effective)")
    delete_parser.add_argument("--force", action="store_true", help="Force delete without recovery window")
    delete_parser.add_argument("secret_name", help="Name of the secret to delete")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Use the provider directly from args, since it's now defined in each subcommand
    provider = args.provider if hasattr(args, 'provider') else 'secretsmanager'
    
    if args.command == "list":
        secret_manager = SecretManager(provider_type=provider, region_name=args.region)
        secrets = secret_manager.list_secrets()
        print(f"Available secrets ({provider}):")
        for secret in secrets:
            print(f"- {secret}")
        return 0
    
    elif args.command == "get":
        secret_manager = SecretManager(provider_type=provider, region_name=args.region)
        secret_data = secret_manager.get_secret(args.secret_name)
        
        if not secret_data:
            logger.error(f"No secret data found for {args.secret_name}")
            return 1
            
        print(json.dumps(secret_data, indent=2))
        return 0
    
    elif args.command == "create":
        secret_manager = SecretManager(provider_type=provider, region_name=args.region)
        
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
        secret_manager = SecretManager(provider_type=provider, region_name=args.region)
        
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
        secret_manager = SecretManager(provider_type=provider, region_name=args.region)
        
        # Check if secret exists
        if args.secret_name not in secret_manager.list_secrets():
            logger.error(f"Secret {args.secret_name} does not exist.")
            return 1
        
        success = secret_manager.delete_secret(args.secret_name, args.force)
        return 0 if success else 1
    
    elif args.command == "run":
        secret_manager = SecretManager(provider_type=provider, region_name=args.region)
        secret_data = secret_manager.get_secret(args.secret)
        
        if not secret_data:
            logger.error(f"No secret data found for {args.secret}")
            return 1
        
        # Prepare environment variables from secrets
        env_vars = {}
        for key, value in secret_data.items():
            env_name = f"{args.prefix}{key.upper()}" if args.prefix else key.upper()
            env_vars[env_name] = str(value)
        
        # Log the secrets being injected (keys only for security)
        logger.info(f"Injecting secrets: {', '.join(env_vars.keys())}")
        
        # Run the command with the environment variables
        cmd = [args.app] + args.app_args
        return run_command(cmd, env_vars)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())