import pickle
from tkinter import mainloop
from pip import main
import ruamel.yaml as yaml
import ruamel
import re
from hashlib import sha256
import requests
from pprint import pprint
import semantic_version
import json
import argparse
from tqdm import tqdm
import time

from dateutil.parser import isoparse

parser = argparse.ArgumentParser(description='')
parser.add_argument("--wf", dest='workflowfile', type=str)
parser.add_argument("--dest", dest="destination", type=str)
args = parser.parse_args()

# get position of string ": name:" in a file
from typing import Dict, List

event_rank = {
    "fork": 3,
    "issue_comment": 3,
    "issues": 3,
    "pull_request_comment": 3,
    "watch": 3,
    "discussion": 3,  # new added event
    "discussion_comment": 3,  # new added event
    "pull_request": 2,
    "pull_request_target": 2,
    "repository_dispatch": 2,  # new added event
    "pull_request_review": 1,
    "pull_request_review_comment": 1,
    "push": 1,
    "release": 1,
    "workflow_call": 1,
    "workflow_dispatch": 1,
    "workflow_run": 1,
    "schedule": 1,  # new added event
    "merge_group": 1,  # new added event
    "branch_protection_rule": 1,  # new added event
    "check_run": 1,  # new added event
    "check_suite": 1,  # new added event
    "create": 1,  # new added event
    "delete": 1,  # new added event
    "deployment": 1,  # new added event
    "deployment_status": 1,  # new added event
    "gollum": 1,  # new added event
    "label": 1,  # new added event
    "milestone": 1,  # new added event
    "page_build": 1,  # new added event
    "public": 1,  # new added event
    "registry_package": 1,  # new added event
    "status": 1,  # new added event
    "project_card": 1, # new added event (aborded now, but exist in the past workflow files。) 
}



def get_position(file_name, string):
    indexes = []
    with open(file_name, 'r') as f:
        for i, line in enumerate(f):
            if string in line:
                indexes.append(i + 1)
    return indexes

# Separate a string based on a patter similar to "#example\nname: example"
def separate_string(string):
    rex = r"___WORKFLOW END___\n"
    found = re.findall(rex, string)
    print(found)
    indx = []
    for e, i in enumerate(found):
        indx.append((string.find(i), string.find(found[e + 1]) if e + 1 < len(found) else -1))
    return indx


def extract_workflow(sample):
    
    output = dict()
    exceptions = []
    
    try:
        workflow = yaml.round_trip_load(sample)
    
        output['name'] = workflow.get('name')
        output['permissions'] = repr(workflow.get('permissions'))
        output['conditional'] = workflow.get('if')

        if isinstance(workflow['on'], str):
            output['events'] = {"type": workflow.get('on'), "security_rank": event_rank[workflow.get('on')]}
        elif isinstance(workflow['on'], list):
            output['events'] = [{"type": workflow.get('on')[i], "security_rank": event_rank[workflow.get('on')[i]]} for i in
                                range(len(workflow['on']))]
        elif isinstance(workflow['on'], dict):
            output['events'] = []
            for event in workflow.get('on'):
                if isinstance(workflow.get('on')[event], dict):
                    output['events'].append({"type": event, "security_rank": event_rank[event], "filters": [k for k in workflow.get('on')[event].keys()]})
                else:
                    output['events'].append({"type": event, "security_rank": event_rank[event]})
        else:
            assert False, f'Unsupported type {type(workflow.get("on"))} for workflow.on field'

        jobs = workflow.get('jobs', dict())
        output['jobs'] = extract_jobs(jobs, True if workflow.get('if') else False)
        
    except Exception as e:
        return False
    
    return output


def extract_jobs(jobs, conditional_wf):
    output = dict()

    for id, job in jobs.items():
        output[id] = dict()

        output[id]['name'] = job.get('name')
        output[id]['uses'] = job.get('uses')
        output[id]['conditional'] = job.get('if')
        output[id]['permissions'] = job.get('permissions')
        output[id]['steps'] = extract_steps(job.get('steps', []), True if job.get('if') else False, conditional_wf)

    return output


def extract_steps(steps, conditional_job, conditional_wf):
    output = []

    for i, step in enumerate(steps):
        item = dict()

        item['name'] = step.get('name')
        item['conditional'] = step.get('if')
        item['position'] = i + 1
        item['uses'] = step.get('uses', None)
        _run = step.get('run', None)
        item['security'] = {}
        if step.get('uses', None):
            item['security'].update({"Action existed": True})
        if _run is not None:
            item['run'] = len(str(_run).split('\n'))
            item['run_hash'] = sha256(str.encode(str(_run))).hexdigest()
            item['security'] = {"runs": run_analyzer(step, conditional_wf, conditional_job)}
            item['secrets'] = {"runs": secret_analyzer(step)}
        else:
            item['run'] = 0
        output.append(item)

    return output


def perms_analyzer(wf):
    wf_name, wf_dict = wf
    if wf_dict['permissions']:
        print(f"Workflow has permissions: {wf_dict['permissions']}")
    for job in wf_dict['jobs'].keys():
        if wf_dict['jobs'][job]['permissions']:
            print(f"Job {job} has permissions: {wf_dict['jobs'][job]['permissions']}")


def run_analyzer(step: Dict[str, any], cond_wf: bool, cond_job: bool) -> List[Dict[str, any]]:
    rex = r".*(\${{\s*github\.).*"
    ret = []
    if step['run']:
        for i, l in enumerate(str(step['run']).split("\n")):
            if re.match(rex, l):
                if step.get('if', None) or cond_wf or cond_job:
                    ret.append({"position": i, "line": l, "conditional": True})
                else:
                    ret.append({"position": i, "line": l, "conditional": False})
                    
    return ret


def secret_analyzer(step: Dict[str, any]):
    secret_re = r".*(secrets\.).*"
    ret = []

    if step['run']:
        for i, l in enumerate(str(step['run']).split("\n")):
            if re.match(secret_re, l):
                if 'contrib/charts/dragonfl' in l:
                    print(l)
                ret.append({"line": l, "secret": "SECRET_OUT_ENV"})
                
    return ret 


def workflow_analyzer(wf):
    wf_name, wf_dict = wf
    for job in wf_dict['jobs'].keys():
        for step in wf_dict['jobs'][job]['steps']:
            run_analyzer(job, step, wf_dict['conditional'], wf_dict['jobs'][job]['conditional'])
            secret_analyzer(job, step)

            
if __name__ == "__main__":
    
    wfs = []
    print("Starting workflow analysis...")
    with open(args.workflowfile, encoding='utf-8', errors="replace") as f:
        dat = f.read()
        count_wf = 0
        exceptions = []
        for index,wf in tqdm(enumerate(dat.split("___WORKFLOW END___\n"))):
            #print(wf + "---------------------\n")
            if wf != "":
                wf_lines = wf.split("\n")
                repo_time = wf_lines[0]
                wf_name = str(count_wf) + " " + wf_lines[1].replace("name: ", "").replace('\"',"") 
                wf_content = "\n".join(wf_lines[1:])
                count_wf += 1
                
                if wf_content.find(u'\x04') > 0:
                    print(wf_content[wf_content.find(u'\x04'):])
                
                if extract_workflow(wf_content):     
                    wfs.append((wf_name, extract_workflow(wf_content)))
                else:
                    exceptions.append(index)

    
    print(f"Workflows with following indexes raised exceptions: {exceptions}")
    
    wfs_dict = dict()
    for w in wfs:
        if 'jobs' not in w[1].keys():
            print(f"No jobs found in workflow {w[0]}")
            continue
        if w[0] not in wfs_dict.keys():
            wfs_dict.update({w[0]: []})
        wfs_dict[w[0]].append(w[1])
        
        pure_wfs = []
        for v in wfs_dict.values():
                pure_wfs.append(v)
                
    with open(args.destination, "wb") as f:
        pickle.dump(pure_wfs, f)