import pathlib,tempfile,json,dataclasses,types
from build import BuildPlan,ApprovedProjectBuilder
from build.approval import authorize_plan
import build_check as helper
BASE=pathlib.Path(__file__).parent
backend=helper.BACKEND.replace('record("wheel")','record("wheel")\n    record("config="+str(config_settings))')
results=[]
with tempfile.TemporaryDirectory(dir=BASE/'contract-tmp') as root:
 for mode in ['changed_plan_copy','unchanged_plan_control']:
  p=pathlib.Path(root)/mode;p.mkdir();src,log=helper.fixture(p,backend);plan=BuildPlan.create(src,hooks=['build_wheel'],config_settings={'mode':'reviewed'})
  modified=dataclasses.replace(plan,config_settings=types.MappingProxyType({'mode':'unapproved'})) if mode=='changed_plan_copy' else plan
  try:
   with authorize_plan(plan) as authorization:
    with ApprovedProjectBuilder(modified,authorization) as builder:builder.build_wheel(p/'dist')
   executed=True;error=None
  except Exception as e:executed=False;error=type(e).__name__
  actual=helper.events(log);passed=not executed if mode=='changed_plan_copy' else executed
  results.append({'case':mode,'status':'PASS' if passed else 'FAIL','executed':executed,'error':error,'backend_events':actual})
print(json.dumps({'scope':'public dataclasses.replace creates changed canonical config while retaining prior digest; no private object mutation or source patch','results':results},indent=2))