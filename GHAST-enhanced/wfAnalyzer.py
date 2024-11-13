import json
import re
import pickle
from enum import Enum
import argparse
from tqdm import tqdm

parser = argparse.ArgumentParser(description='')
parser.add_argument("--src", dest='source', type=str)
parser.add_argument("--dest", dest="dest", type=str)
args = parser.parse_args()

verified_publishers = ['actions',
 'advanced-security',
 'anchore',
 'aquasecurity',
 'astral-sh',
 'atlassian',
 'aws-actions',
 'azure',
 'bridgecrewio',
 'bufbuild',
 'buildkite',
 'cloudflare',
 'cloudsmith-io',
 'codacy',
 'codecov',
 'codesee-io',
 'codspeedhq',
 'datadog',
 'deepsourcelabs',
 'denoland',
 'depot',
 'determinatesystems',
 'devcontainers',
 'digicert',
 'digitalocean',
 'docker',
 'expo',
 'game-ci',
 'getsentry',
 'git-for-windows',
 'github',
 'google-github-actions',
 'gradle',
 'grafana',
 'hashicorp',
 'iterative',
 'jetbrains',
 'jfrog',
 'launchdarkly',
 'matlab-actions',
 'microsoft',
 'newrelic',
 'nrwl',
 'octokit',
 'okteto',
 'oracle-actions',
 'orijtech',
 'ossf',
 'oxsecurity',
 'pdm-project',
 'pre-commit-ci',
 'pulumi',
 'pypa',
 'readmeio',
 'redhat-actions',
 'renovatebot',
 'ruby',
 'rubygems',
 'saucelabs',
 'shopify',
 'sigstore',
 'slackapi',
 'sonarsource',
 'sourcegraph',
 'stackrox',
 'step-security',
 'tailscale',
 'testspace-com',
 'trufflesecurity',
 'trunk-io',
 'zaproxy']

class critical_gh_context(Enum):
    ACTOR = "github.actor"
    PULL_REQUEST_BODY = "github.event.pull_request.body"
    PULL_REQUEST_TITLE = "github.event.pull_request.title"
    ISSUE_TITLE = "github.event.issue.title"
    ISSUE_BODY = "github.event.issue.body"
    ISSUE_COMMENT_BODY = "github.event.issue_comment.body"
    PULL_REQUEST_COMMENT_BODY = "github.event.pull_request_review_comment.body"


class critical_secrets(Enum):
    SECRET_CDD = "secrets."

class critical_infos(Enum):
    TWITTER_TOKEN = r"[1-9][0-9]+-[0-9a-zA-Z]{40}"
    FACEBOOK_TOKEN =  r"EAACEdEose0cBA[0-9A-Za-z]+"
    YOUTUBE_API_KEY = r"AIza[0-9A-Za-z\-_]{35}"
    YOUTUBE_OAUTH_ID = r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"
    PICATIC_API_KEY = r"sk_live_[0-9a-z]{32}"
    STRIPE_STANDARD_API_KEY = r"sk_live_[0-9a-zA-Z]{24}"
    STRIPE_RESTRICTED_API_KEY = r"rk_live_[0-9a-zA-Z]{24}"
    SQUARE_ACCESS_TOKEN = r"sq0atp-[0-9A-Za-z\-_]{22}"
    SQUARE_OAUTH_SECRET = r"sq0csp-[0-9A-Za-z\-_]{43}"
    PAYPAL_BRAINTREE_ACCESS_TOKEN = r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
    AMAZON_MWS_AUTH_TOKEN = r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    TWILIO_API_KEY = r"SK[0-9a-fA-F]{32}"
    MAILGUN_API_KEY = r"key-[0-9a-zA-Z]{32}"
    MAILCHIMP_API_KEY = r"[0-9a-f]{32}-us[0-9]{1,2}"
    AWS_ACCESS_KEY_ID = r"AKIA[0-9A-Z]{16}"
    AWS_SECRET_ACCESS_KEY = r"(?<!@)(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])*" 
    

class critical_permissions(Enum):
    ONLY_WF_DECLARATION = "Permissions declaration at workflow level"
    NO_DECLARATION = "Permissions are not declared in the workflow"
    PERMS_DISCREPANCY = "Permissions do not match the required ones"

class critical_tp_workflow(Enum):
    WF_OOD = "Workflow out of date"
    NO_PINNING = "Workflow not pinned at commit"

def getActions(wf):
    _actions = []
    for j in wf['jobs']:
        for s in wf['jobs'][j]['steps']:
            sec = s.get('security', None)
            if sec:
                if sec.get('Action existed'):
                    _actions.append((j, s.get('uses')))

    return _actions

def getRuns(wf):
    _runs = []
    for j in wf['jobs']:
        for s in wf['jobs'][j]['steps']:
            sec = s.get('security')
            if sec.get('runs'):
                _runs.append((j, sec.get('runs')))
    return _runs
                
def getSecrets(wf):
    _secrets = []
    for j in wf['jobs']:
        for s in wf['jobs'][j]['steps']:
            if 'secrets' in s:
                sec = s.get('secrets')
                if sec.get('runs'):
                    _secrets.append((j, sec.get('runs')))
    return _secrets


def getPerms(wf):
    _perms = {}
    _perms.update(wf=wf.get('permissions', None), jobs={})
    for j in wf['jobs']:
        _perms['jobs'].update({j: wf['jobs'][j].get('permissions')})
    return _perms


def main():
    listwf = pickle.load(open(f"{args.source}", "rb"))
    commit_rex = r"[0-9a-f]{40}"

    vulns = []
    for wf_file in tqdm(listwf):
        
        wf_details = {}
        for wf in wf_file:
            
            _runs = getRuns(wf)
            _actions = getActions(wf)
            _perms = getPerms(wf)
            _secrets = getSecrets(wf)

            wf_details.update({wf.get('name'): {'events': [], "issues": []}})

            if isinstance(wf.get('events'), dict):
                wf_details[wf.get('name')]['events'].append((wf.get('events').get('type'), wf.get('events').get('security_rank')))
            else:
                for e in wf.get('events'):
                    wf_details[wf.get('name')]['events'].append((e.get('type'), e.get('security_rank')))
                    
            if _runs != []:
                
                for run in _runs:
                    for i in critical_gh_context:
                        if i.value in ''.join(run[1][0]['line']):
                            wf_details[wf.get('name')]['issues'].append((run[0],''.join(run[1][0]['line']),i.name))
                    
            if _secrets != []:

                for secret in _secrets:
                    for s in secret[1]:
                        wf_details[wf.get('name')]['issues'].append((secret[0],s['line'],s['secret']))

            
            if len(_perms) > 0:
                wf_perms = False
                if _perms.get('wf') != 'None':
                    wf_perms = True
                for job_name, job_p in _perms.get('jobs').items():
                    if not job_p and wf_perms:
                        wf_details[wf.get('name')]['issues'].append((job_name, critical_permissions.ONLY_WF_DECLARATION.name))
                    elif not job_p and not wf_perms:
                        wf_details[wf.get('name')]['issues'].append((job_name, critical_permissions.NO_DECLARATION.name))
            

            if len(_actions) > 0:
                for ood in _actions:
                    
                    if ood[1].startswith('docker:') == False and ood[1].startswith('./') == False and len(ood[1].split('/')) < 3:

                        if ood[1].split('/')[0].lower() not in verified_publishers:

                            if "@" in ood[1]:
                                if not re.match(commit_rex, ood[1].split("@")[-1]):
                                    wf_details[wf.get('name')]['issues'].append((ood[0], ood[1], critical_tp_workflow.NO_PINNING.name))

                            else:
                                wf_details[wf.get('name')]['issues'].append((ood[0], ood[1], critical_tp_workflow.NO_PINNING.name))

        vulns.append(wf_details)

    with open(f"{args.dest}", "w") as f:
        f.write(json.dumps(vulns))

if __name__ == "__main__":
    main()




