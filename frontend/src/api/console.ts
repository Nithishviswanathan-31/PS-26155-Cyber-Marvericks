import { authFetch as fetch } from "./http";
import { API_BASE_URL, AnalysisApiError } from "./analyze";
export type ConsolePage={items: Record<string, unknown>[];total:number;offset:number;limit:number};
export async function consoleGet(path:string):Promise<Record<string,unknown>|ConsolePage>{const r=await fetch(`${API_BASE_URL}${path}`);const p=await r.json().catch(()=>null);if(!r.ok||!p)throw new AnalysisApiError("Console data could not be loaded.",r.status);return p;}
