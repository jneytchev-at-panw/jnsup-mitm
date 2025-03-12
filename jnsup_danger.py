"""
Extract and coordinate data for a report on suppressions from Prisma Cloud CAS
"""
import json
import os
import sys, time
import requests as req
import argparse
from datetime import datetime, timezone

api = os.getenv('PRISMA_API_URL')
username = os.getenv('PRISMA_ACCESS_KEY_ID')
password = os.getenv('PRISMA_SECRET_KEY')
if ( api is None or username is None or password is None):
    print('Missing environment variables')
    sys.exit(1)
auth_ts = 0.0

"""
Check the result of a restful API call
"""
def result_ok(result, message):
    if ( not result.ok ):
        print(message)
        result.raise_for_status()

"""
Authenticate against Prisma cloud. Return authentication JWT token
"""
def auth_prisma():
    global auth_ts
    payload = { 'username': username, 'password': password }
    headers = { 
        'Content-Type': 'application/json; charset=UTF-8', 
        'Accept': 'application/json; charset=UTF-8' 
    }
    result = req.post(f"{api}/login", data=json.dumps(payload), headers=headers)
    result_ok(result,'Could not authenticate to Prisma.')

    auth_ts = datetime.now().timestamp()

    return result.json()['token']

"""
Create headers for the RESTful API calls. Returns a headers object.
"""
def get_headers(token):
    return { 
        'Content-Type': 'application/json; charset=UTF-8', 
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': token
    }


def re_auth():
    global headers
    if (datetime.now().timestamp() - auth_ts) / 60 > 9.0:
        headers = get_headers(auth_prisma())
        #print(f'{datetime.now().strftime("%I:%M%p on %B %d, %Y")} ===re_auth===')

"""
Get all repos
"""
def get_all_repos():
    print('Getting all repos.')
    url = f"{api}/code/api/v1/repositories"
    result = req.get(url, headers=headers)
    result_ok(result, 'Could not retrieve repositories.')
    return result.text


"""
Get unique owners from all repos
"""
def get_all_owners():
    print('Getting unique owners from repos.')
    repos = json.loads(get_all_repos())
    owners = []
    for r in repos:
        if r['owner'] not in owners:
            owners.append(r['owner'])
    return owners

"""
Get resource suppressions
"""
def get_resource_suppressions(accountFilter):
    #print('Getting all suppressions.')
    url = f"{api}/code/api/v1/suppressions"
    result = req.get(url, headers=headers)
    result_ok(result, 'Could not retrieve suppressions.')
    run_config = get_run_config()
    resource_suppressions = []
    allsups = json.loads(result.text) 
    #print(f"allsups: {len(allsups)}")
    for s in allsups:
        if s['suppressionType'] == 'Resources':
            supp = {}
            policyId = s['policyId']
            policySev = 'UNKNOWN'
            # Is it a custom policy?
            if policyId.count('_') == 2:
                for cp in run_config['customPolicies']:
                    if policyId == cp['id']:
                        policySev = cp['pcSeverity']
                        break
            field = ''
            # Is it an existing checkov policy
            if policyId.startswith('BC_'):
                field = 'id'
            else:
                field = 'pcPolicyId'
            # Lookup severity
            for pm in run_config['policyMetadata']:
                if policyId == run_config['policyMetadata'][pm][field]:
                    policySev = run_config['policyMetadata'][pm]['pcSeverity']
                    break
            acctId = ''
            justification = []
            for r in s['resources']:
                acctId = r['accountId']
                if accountFilter is None or acctId == accountFilter:
                    re_auth()
                    justification = get_justification(policyId, acctId)
                    supp =  { 'suppressionId': s['id'], 'policyId': policyId, 'policySeverity': policySev, 'accountId': acctId, 'creationDate': s['creationDate'], 'justification': justification }
                    resource_suppressions.append(supp)                    
            time.sleep(1)
    return resource_suppressions

"""
Get justification by policyId and accountId, filter by suppression type
"""
def get_justification(policyId, accountId, suppType='Resources'):
    url = f"{api}/code/api/v1/suppressions/{policyId}/justifications?accounts={accountId}"
    # print(datetime.now().strftime("%I:%M%p on %B %d, %Y"))
    # print(f"get_justification: {url}")
    result = req.get(url, headers=headers)
    result_ok(result, f"Could not retrieve justification for policy {policyId}, account {accountId}")
    # Filter non justifications by suppression type
    alljusts = json.loads(result.text)
    filtered_justifications = []
    for j in alljusts:
        if j['suppressionType'] == suppType:
            filtered_justifications.append(j)
    return filtered_justifications


def filter_suppressions_by_owner(supps: list, owner: str) ->list:
    result = []
    for s in supps:
        if s['justification']:
            for j in s['justification']:
                if j['owner'] == owner:
                    result.append(j)
    return result


"""
Delete suppression by suppressionId and policyId
"""
def delete_suppression(policyId, suppressionId) -> str:
    #print(f"Deleting suppression {suppressionId} of policy {policyId}")
    url = f"{api}/code/api/v1/suppressions/{policyId}/justifications/{suppressionId}"
    result = req.delete(url, headers=headers)
    result_ok(result, f"Failed to delete suppression {suppressionId} of policy {policyId}")
    return f"Deleted {policyId}:{suppressionId}"

def get_all_repos():
   #print('Getting all repositories.')
    url = f"{api}/code/api/v1/repositories"
    result = req.get(url, headers=headers)
    result_ok(result, 'Could not retrieve repositories.')
    return result.json()

def get_suppressions_by_type(suptype: str) ->list:
    url = f"{api}/code/api/v1/suppressions"
    result = req.get(url, headers=headers)
    result_ok(result, 'Could not retrieve suppressions.')
    #run_config = get_run_config()
    suppressions = []
    allsups = json.loads(result.text) 
    for s in allsups:
        if s['suppressionType'] == suptype:
            suppressions.append(s)
    
    return suppressions

"""
Undocumented API call: get running configuration
"""
def get_run_config():
    #print('Getting running configuration.')
    url = f"{api}/code/api/v2/checkov/runConfiguration?module=pc"
    result = req.get(url, headers=headers)
    result_ok(result, 'Could not retrieve running congiguration.')
    return result.json()

def get_all_v2_config_policies():
    #print('Getting all config policies.')
    url = f"{api}/v2/policy?policy.type=config&policy.subtype=build"
    result = req.get(url, headers=headers)
    result_ok(result, 'Could not retrieve policies.')
    return result.json()

def get_all_tags():
    #print('Getting all tags.')
    url = f"{api}/code/api/v1/tag-rules"
    result = req.get(url, headers=headers)
    result_ok(result, 'Could not retrieve tags.')
    return result.json()

"""
Find all resource suppressions that are older than :max_age: days
"""
def delete_older_resource_suppressions(suppressions: list, max_age: int) ->list:
    now = datetime.now(tz=timezone.utc)
    result = []
    for s in suppressions:
        for j in s['justification']:
            sup_created = datetime.fromtimestamp(j['date']/1000, tz=timezone.utc)
            sup_age = (now - sup_created).days
            if sup_age > max_age:
                result.append({ 'policyId': s['policyId'], 
                               'suppressionId': j['id'], 
                               'age': sup_age  })
                # To delete, uncomment below line. Note: only Sysadmins can delete objects
                #print(f"Deleting resource suppression {j['id']} of policy {s['policyId']} created {sup_age} days ago.")
                #delete_suppression(s['policyId'], j['id'])
    return result

def delete_by_justification(justification: list):
    re_auth()
    for j in justification:
        delete_suppression(j['violationId'],j['id'])

"""
Find all repo type suppressions older than :max_age: days and delete them
"""
def delete_older_repo_suppressions(runconfig: list, max_age: int) -> list:
    now = datetime.now(tz=timezone.utc)
    result = []
    for sup in runconfig['suppressions']:
        if sup['suppressionType'] == 'Accounts':
            creation_date = datetime.fromisoformat(sup['creationDate'])
            sup_age = (now - creation_date).days
            if sup_age > max_age:
                result.append({'policyId': sup['policyId'], 
                               'suppressionId': sup['id'], 
                               'age': sup_age})
                # Uncomment to delete
                #print(f"Deleting resource suppression {sup['id']} of policy {sup['policyId']} created {sup_age} days ago.")
                #delete_suppression(sup['policyId'],sup['id'])
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Suppression export from Prisma Cloud')
    parser.add_argument('-r','--repofilter', help='Filter by a single repository <owner/repo>')
    parser.add_argument('-a','--age', help='Delete resource suppressions older than <age> days', type=int, default=14)
    args = parser.parse_args()
    headers = get_headers(auth_prisma())

    suppressions = get_resource_suppressions(args.repofilter)
    # byowner = filter_suppressions_by_owner(suppressions,'jneytchev@paloaltonetworks.com')
    # print(json.dumps(byowner))
    # delete_by_justification(byowner)
    # print('Done')
    print(json.dumps(suppressions))
