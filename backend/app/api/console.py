from fastapi import APIRouter, Query
from ..storage.database import console_analyses, console_batches, console_configurations, console_devices, list_knowledge

router=APIRouter(prefix="/api", tags=["auditor console"])
def page(items,total,offset,limit): return {"items":items,"total":total,"offset":offset,"limit":limit}

@router.get("/analyses")
def analyses(vendor:str|None=None, device_id:str|None=None, status:str|None=None, q:str|None=None, offset:int=Query(0,ge=0), limit:int=Query(50,ge=1,le=100)):
    items,total=console_analyses(vendor=vendor,device_id=device_id,status=status,query=q,offset=offset,limit=limit); return page(items,total,offset,limit)
@router.get("/devices")
def devices(q:str|None=None,offset:int=Query(0,ge=0),limit:int=Query(50,ge=1,le=100)):
    items,total=console_devices(query=q,offset=offset,limit=limit); return page(items,total,offset,limit)
@router.get("/configurations")
def configurations(q:str|None=None,offset:int=Query(0,ge=0),limit:int=Query(50,ge=1,le=100)):
    items,total=console_configurations(query=q,offset=offset,limit=limit); return page(items,total,offset,limit)
@router.get("/batches")
def batches(offset:int=Query(0,ge=0),limit:int=Query(50,ge=1,le=100)):
    items,total=console_batches(offset=offset,limit=limit); return page(items,total,offset,limit)
@router.get("/findings")
def findings(vendor:str|None=None,status:str|None=None,device_id:str|None=None,control_id:str|None=None):
    items,_=console_analyses(vendor=vendor,device_id=device_id,status=status,limit=1000); return [dict(result=result,analysis_id=item["analysis_id"],vendor=item["vendor"],device=item["device"],configuration=item["configuration"],evidence=[e for e in item.get("evidence",[]) if e.get("control_id")==result.get("control_id")]) for item in items for result in item["results"] if (control_id is None or result.get("control_id")==control_id)]
@router.get("/dashboard/summary")
def summary():
    analyses,total=console_analyses(limit=10000); devices,device_total=console_devices(limit=10000); configs,config_total=console_configurations(limit=10000); batches,batch_total=console_batches(limit=10000); roots=[a for a in analyses]
    return {"total_devices":device_total,"total_configurations":config_total,"total_analyses":total,"batch_analyses":batch_total,"pass_findings":sum(a["pass_findings"] for a in roots),"fail_findings":sum(a["fail_findings"] for a in roots),"unknown_findings":sum(a["unknown_findings"] for a in roots),"recent_analyses":analyses[:10],"recent_unknown_patterns":[p for a in analyses for p in a["unknown_patterns"]][:10],"pending_ai_reviews":0,"active_knowledge_entries":len(list_knowledge(status="ACTIVE"))}
@router.get("/knowledge/review-queue")
def knowledge_review_queue():
    return {"pending_proposals":[],"conflicts":[],"deactivated_knowledge":list_knowledge(status="DEACTIVATED"),"active_knowledge":list_knowledge(status="ACTIVE")}
