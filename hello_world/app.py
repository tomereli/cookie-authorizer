from http.cookies import SimpleCookie
from jose import jwk, jwt
from jose.utils import base64url_decode
import json
import traceback
import sys

def get_auth_token_from_cookie(event):
    print("event=",event)
    try:
        cookie = SimpleCookie()
        cookie.load(event["headers"]["cookie"])
        return cookie["token"].value
    except:
        print("Problem retrieving Token Cookie from request")
        print(traceback.format_exc())
        raise Exception("Problem retrieving Token Cookie from request")

def generatePolicy(tenant_id, effect, methodArn):
    authResponse = {}
    base = methodArn.split("/")[0]
    stage = methodArn.split("/")[1]
    arn = base + "/" + stage + "/*/*"

    if effect and methodArn:
        policyDocument = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FirstStatement",
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": arn,
                }
            ],
        }
        authResponse["policyDocument"] = policyDocument
        authResponse["context"] = {
            "tenant_id": tenant_id
        }
    return authResponse

def lambda_handler(event, context):
    try:
        token = get_auth_token_from_cookie(event)
        print("token=",token)
        unauthorized_claims = jwt.get_unverified_claims(token)
        print("claims=",unauthorized_claims)
        # JWT Token validations goes here
        # Additional claims based validation goes here
        company = unauthorized_claims["custom:company"]
        email = unauthorized_claims["email"]
        role = unauthorized_claims["custom:role"]
        tenant_id = unauthorized_claims["custom:tenant_id"] # TODO replace with get from Cognito

        print(f"SUCCESS: tenant_id={tenant_id}, company={company}, role={role}, email={email}")
        return generatePolicy(tenant_id, "Allow", event["methodArn"])
    except Exception as e:
        print(e)
        return generatePolicy(None, "Deny", event["methodArn"])

