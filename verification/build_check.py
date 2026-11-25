"""Independent local PEP517 approval probes; no model test helpers are imported."""
import json,os,pathlib,subprocess,sys,tempfile
from build import BuildPlan,ApprovedProjectBuilder,ProjectBuilder,BuildBackendException
from build.approval import authorize_plan,build_authorized,ApprovalCancelled,PlanChangedError,HookNotAuthorizedError,AuthorizationError,CancellationToken
BASE=pathlib.Path(__file__).parent
CACHE=pathlib.Path(r'D:\hc\userFeedback\cache').resolve()
assert BASE.resolve().is_relative_to(CACHE)
BACKEND='''import json,os,pathlib
TAG = "original"
def record(event):
    with pathlib.Path(os.environ["BUILD_AUDIT_LOG"]).open("a",encoding="utf8") as f: f.write(json.dumps({"event":event,"tag":TAG})+"\\n")
record("import")
def get_requires_for_build_wheel(config_settings=None):
    record("requires")
    return ["local-dynamic==1.0"]
def build_wheel(wheel_directory,config_settings=None,metadata_directory=None):
    record("wheel")
    if config_settings and config_settings.get("fail")=="yes": raise RuntimeError("synthetic backend failure")
    p=pathlib.Path(wheel_directory);p.mkdir(parents=True,exist_ok=True);name="local_fixture-1.0-py3-none-any.whl";(p/name).write_bytes(b"PK harmless local fixture");return name
def prepare_metadata_for_build_wheel(metadata_directory,config_settings=None):
    record("metadata")
    p=pathlib.Path(metadata_directory)/"local_fixture-1.0.dist-info";p.mkdir(parents=True,exist_ok=True);(p/"METADATA").write_text("Metadata-Version: 2.1\\nName: local-fixture\\nVersion: 1.0\\n");return p.name
'''
def fixture(root,backend=BACKEND):
    src=root/'project';src.mkdir();(src/'backend').mkdir();(src/'backend/probe_backend.py').write_text(backend,encoding='utf8');(src/'pyproject.toml').write_text('[build-system]\nrequires=[]\nbuild-backend="probe_backend"\nbackend-path=["backend"]\n',encoding='utf8');log=root/'events.log';os.environ['BUILD_AUDIT_LOG']=str(log);return src,log

def events(log):
    return [json.loads(s) for s in log.read_text().splitlines() if s] if log.exists() else []
def blocked(fn,classes=(PlanChangedError,AuthorizationError)):
    try:fn()
    except classes as e:return type(e).__name__
    raise AssertionError('Operation was unexpectedly accepted')
def planning(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel'],config_settings={'mode':'reviewed'});assert not events(log) and p.dynamic_dependencies is None and p.backend_name=='probe_backend' and 'backend/probe_backend.py' in p.file_digests and p.config_settings['mode']=='reviewed';return {'imports':0,'dynamic_dependencies':'unknown','files':len(p.file_digests)}
def authorized(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel'])
    with authorize_plan(p) as a:
        with ApprovedProjectBuilder(p,a) as b:result=b.build_wheel(root/'dist');assert pathlib.Path(result).exists();assert pathlib.Path(b.frozen_source_path)!=src
    rows=events(log);assert [r['event'] for r in rows]==['import','wheel'];return {'imports':1,'wheel_calls':1}
def changed_pyproject(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel']);(src/'pyproject.toml').write_text((src/'pyproject.toml').read_text()+'\n[project]\nname="changed"\n');name=blocked(lambda:authorize_plan(p));assert not events(log);return {'rejected':name,'imports':0}
def changed_backend(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel'])
    with authorize_plan(p) as a:
        (src/'backend/probe_backend.py').write_text(BACKEND.replace('"original"','"changed"'))
        name=blocked(lambda:ApprovedProjectBuilder(p,a))
    assert not events(log);return {'rejected':name,'imports':0}
def callback_source_race(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel']);calls=[]
    def runner(cmd,cwd=None,extra_environ=None):
        calls.append(cwd);(src/'backend/probe_backend.py').write_text(BACKEND.replace('"original"','"changed"'));__import__('pyproject_hooks').default_subprocess_runner(cmd,cwd,extra_environ)
    with authorize_plan(p) as a:
        with ApprovedProjectBuilder(p,a,runner=runner) as b:b.build_wheel(root/'dist')
    rows=events(log);assert len(calls)==1 and rows and all(r['tag']=='original' for r in rows);return {'runner_calls':1,'executed_tag':rows[-1]['tag']}
def changed_config(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel'],config_settings={'mode':'reviewed'})
    with authorize_plan(p) as a:
        with ApprovedProjectBuilder(p,a) as b:name=blocked(lambda:b.build_wheel(root/'dist',config_settings={'mode':'other'}))
    assert not events(log);return {'rejected':name,'imports':0}
def callback_config_mutation(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel'],config_settings={'mode':'reviewed'})
    def approve(plan):plan.config_settings['mode']='injected';return True
    try:authorize_plan(p,approver=approve)
    except (AuthorizationError,TypeError):pass
    else:raise AssertionError('Mutable approval plan was accepted')
    assert not events(log);return {'imports':0,'mutation_rejected':True}
def metadata_does_not_authorize_wheel(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['prepare_metadata_for_build_wheel'])
    with authorize_plan(p) as a:
        with ApprovedProjectBuilder(p,a) as b:name=blocked(lambda:b.build_wheel(root/'dist'),(HookNotAuthorizedError,))
    assert not events(log);return {'rejected':name,'wheel_calls':0}
def metadata_no_fallback(root):
    src,log=fixture(root,BACKEND.split('def prepare_metadata_for_build_wheel')[0]);p=BuildPlan.create(src,hooks=['prepare_metadata_for_build_wheel'])
    with authorize_plan(p) as a:
        with ApprovedProjectBuilder(p,a) as b:name=blocked(lambda:b.metadata_path(root/'metadata'),(HookNotAuthorizedError,))
    assert not any(r['event']=='wheel' for r in events(log));return {'rejected':name,'wheel_calls':0}
def cancellation(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel']);token=CancellationToken()
    with authorize_plan(p) as a:
        with ApprovedProjectBuilder(p,a,cancellation=token) as b:token.cancel();name=blocked(lambda:b.build_wheel(root/'dist'),(ApprovalCancelled,))
    assert not events(log);return {'rejected':name,'imports':0}
def failure_once(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['build_wheel'],config_settings={'fail':'yes'})
    with authorize_plan(p) as a:
        with ApprovedProjectBuilder(p,a) as b:name=blocked(lambda:b.build_wheel(root/'dist'),(BuildBackendException,))
    assert [r['event'] for r in events(log)]==['import','wheel'];return {'rejected':name,'wheel_calls':1}
class LocalEnvironment:
    python_executable=sys.executable
    def __init__(self):self.installed=[]
    def install(self,requirements):self.installed.append(list(requirements))
    def make_extra_environ(self):return {}
def dynamic_denied(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['get_requires_for_build_wheel','build_wheel']);env=LocalEnvironment()
    with authorize_plan(p) as a:name=blocked(lambda:build_authorized(p,a,output_directory=root/'dist',isolated_environment=env,dependency_approver=lambda requirements:False),(__import__('build').DependencyApprovalRequired,))
    assert not any(r['event']=='wheel' for r in events(log)) and all(not x for x in env.installed);return {'rejected':name,'installed_dynamic':[],'wheel_calls':0}
def dynamic_approved(root):
    src,log=fixture(root);p=BuildPlan.create(src,hooks=['get_requires_for_build_wheel','build_wheel']);env=LocalEnvironment()
    with authorize_plan(p) as a:result=build_authorized(p,a,output_directory=root/'dist',isolated_environment=env,dependency_approver=lambda requirements:requirements==('local-dynamic==1.0',))
    assert pathlib.Path(result).exists() and ['local-dynamic==1.0'] in env.installed and sum(r['event']=='wheel' for r in events(log))==1;return {'installed_dynamic':['local-dynamic==1.0'],'wheel_calls':1}
def legacy(root):
    src,log=fixture(root);result=ProjectBuilder(src).build('wheel',root/'dist');assert pathlib.Path(result).exists() and sum(r['event']=='wheel' for r in events(log))==1;return {'legacy_wheel_calls':1}
def junction_target_change(root):
    src,log=fixture(root);link=src/'backend';one=src/'one';two=src/'two';assert link.resolve().is_relative_to(CACHE) and one.resolve().is_relative_to(CACHE);link.rename(one);two.mkdir();(two/'probe_backend.py').write_text(BACKEND.replace('"original"','"changed"'))
    def junction(target):
        q=subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],capture_output=True);assert q.returncode==0,q.stderr.decode(errors='replace');assert link.is_junction()
    junction(one);p=BuildPlan.create(src,hooks=['build_wheel']);assert not events(log);assert link.is_junction();link.rmdir();junction(two)
    name=blocked(lambda:authorize_plan(p));assert not events(log);assert link.is_junction();link.rmdir();return {'rejected':name,'imports':0,'retarget':'one to two'}
CASES=[planning,authorized,changed_pyproject,changed_backend,callback_source_race,changed_config,callback_config_mutation,metadata_does_not_authorize_wheel,metadata_no_fallback,cancellation,failure_once,dynamic_denied,dynamic_approved,legacy,junction_target_change]
if __name__=='__main__':
    results=[];runtime=BASE/'contract-tmp';runtime.mkdir(exist_ok=True);assert runtime.resolve().is_relative_to(CACHE)
    with tempfile.TemporaryDirectory(dir=runtime) as folder:
        for fn in CASES:
            root=pathlib.Path(folder)/fn.__name__;root.mkdir()
            try:out=fn(root);results.append({'case':fn.__name__,'status':'PASS','observed':out})
            except Exception as e:results.append({'case':fn.__name__,'status':'FAIL','exception':type(e).__name__,'detail':str(e)})
    print(json.dumps({'results':results,'passed':sum(x['status']=='PASS' for x in results),'failed':sum(x['status']=='FAIL' for x in results),'scope':'Independent harmless backend, real subprocess calls; dependency installs are recorded local fixtures, no package downloads.'},indent=2))
    raise SystemExit(1 if any(x['status']=='FAIL' for x in results) else 0)