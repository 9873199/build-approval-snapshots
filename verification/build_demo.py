import dataclasses,types,tempfile,pathlib
import build_check as h
from build import BuildPlan,ApprovedProjectBuilder
from build.approval import authorize_plan
print('Build plan and approval - local runtime check')
with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent/'contract-tmp') as folder:
    folder=pathlib.Path(folder)
    print('Static planning:',h.planning(folder/'plan') if False else 'checking')
    for name in ['planning','authorized','callback_source_race']:
        root=folder/name;root.mkdir();print(name+':',getattr(h,name)(root))
    root=folder/'copied-plan';root.mkdir()
    backend=h.BACKEND.replace('record("wheel")','record("wheel")\n    record("config="+str(config_settings))')
    source,log=h.fixture(root,backend)
    plan=BuildPlan.create(source,hooks=['build_wheel'],config_settings={'mode':'reviewed'})
    altered=dataclasses.replace(plan,config_settings=types.MappingProxyType({'mode':'unapproved'}))
    with authorize_plan(plan) as authorization:
        with ApprovedProjectBuilder(altered,authorization) as builder: builder.build_wheel(root/'dist')
    values=h.events(log)
    print('Approved configuration: mode=reviewed')
    print('Copied plan configuration: mode=unapproved')
    print('Same plan digest:',plan.plan_digest==altered.plan_digest)
    print('Backend actually received:',[x['event'] for x in values if x['event'].startswith('config=')][0])
    print('FAIL: old approval allowed changed configuration')
print('Synthetic local backend; no dependency downloads.')
raise SystemExit(1)
