# ssm-env – Load SSM Param Store into environment

This project is meant to be used as a docker entrypoint for loading keys from SSM Parameter Store into environment variables.

Example usage:

```Dockerfile
ENTRYPOINT ["ssm-env", "-p", "/staging/myapp", "-p", "/staging/common"]
CMD node index.js
```

## AWS Authorization
Default authorization mechanism is used. When running on EC2 or other AWS managed envs it will used the instance role. When running locally aws-cli default profile is used which can be overwritten with AWS standard variables.

### Options
* `--prefix` or `-p` or "$PARAMS_PREFIX" the param store root path to load variables from. Can be specified multiple times
* `--long-env-name` By default only the last part of the key name will be used as var name. Example: `/common/MYVAR` will be exported as `$MYVAR`. When this flag is enabled all path elements after the prefix will be added to var name. Example: `/myapp/common/MYVAR` with prefix "/myapp" will be exported as `$COMMON_MYVAR`

### Procfile support
You can (optionally) place `Procfile` in the working directory and use process names defined there instead of the actual commands.

```sh
# Sample Procfile
web: node ./start-server.js
```

```sh
ssm-env -p /staging/myapp web
```

## Building

```sh
go build ./cmd/ssm-env 
```
