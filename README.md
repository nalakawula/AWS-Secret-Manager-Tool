# AWS Secret Manager Tool

A command-line tool to manage AWS Secrets and inject them as environment variables when running applications. Supports both AWS Secrets Manager and Parameter Store.

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Configure your AWS credentials:
```bash
aws configure
```

## Usage

### Choose a provider

By default, the tool uses AWS Secrets Manager. You can specify Parameter Store for a more cost-effective option:

```bash
python main.py --provider parameterstore [command]
```

### List available secrets

```bash
python main.py list
```

### Get a secret's values

```bash
python main.py get my-secret-name
```

### Create a new secret

With key-value pairs:
```bash
python main.py create new-secret-name username=admin password=secret123
```

With a JSON file:
```bash
python main.py create --file secret.json new-secret-name
```

With description:
```bash
python main.py create --description "My important credentials" new-secret-name username=admin password=secret123
```

### Update an existing secret

```bash
python main.py update existing-secret password=newpassword
```

### Delete a secret

With recovery window (default 30 days):
```bash
python main.py delete my-secret-name
```

Force delete (no recovery window):
```bash
python main.py delete --force my-secret-name
```

### Run a command with secrets injected as environment variables

```bash
python main.py run --secret my-secret-name -- myapp arg1 arg2
```

## Examples

Run a Python script with secrets:
```bash
python main.py run --secret database-credentials -- python my_app.py
```

Run with a prefix for environment variables:
```bash
python main.py run --secret database-credentials --prefix DB_ -- python my_app.py
```

Create a secret for database access:
```bash
python main.py create db-credentials --description "Database access credentials" host=localhost port=5432 username=dbuser password=dbpass
```

Use Parameter Store instead of Secrets Manager:
```bash
python main.py --provider parameterstore create app-config api_key=abc123 timeout=30
```

## Environment Variables

- `AWS_REGION`: Override the default AWS region
- Standard AWS credential environment variables are supported
