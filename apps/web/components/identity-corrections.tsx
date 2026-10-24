"use client";
import { useState } from "react";
import { useCurrentUser } from "@/lib/current-user";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

export interface IdentityCorrection { correction_id: string; subject_id: string; target_id: string; reason: string; actor: string; created_at: string; undone_at: string | null }
export function IdentityCorrections({ records, corrections, onChanged }: { records: Array<{ id:string; label:string }>; corrections:IdentityCorrection[]; onChanged:()=>void }) {
  const admin=useCurrentUser()?.role === "admin";
  const [subject,setSubject]=useState("");const [target,setTarget]=useState("");const [reason,setReason]=useState("");
  const [pending,setPending]=useState(false);const [error,setError]=useState<string|null>(null);
  async function change(undo?:string) {
    setPending(true);setError(null);
    try {
      const response=await fetch(undo ? `/api/v1/tally/inventory/corrections/${encodeURIComponent(undo)}/undo` : "/api/v1/tally/inventory/corrections",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(undo ? {} : {subject_id:subject,target_id:target,reason})});
      if(!response.ok)throw new Error(response.status===409 ? "These records cannot be merged. Refresh and review existing corrections." : "The identity correction could not be saved.");
      setSubject("");setTarget("");setReason("");onChanged();
    }catch(cause){setError(cause instanceof Error?cause.message:"The identity correction could not be saved.");}
    finally{setPending(false);}
  }
  if(!admin)return null;
  return <details className="rounded-lg border p-4 text-sm"><summary className="cursor-pointer font-medium">Review identity corrections</summary>
    <p className="my-3 text-muted-foreground">Merge only when independent source evidence identifies the same person or device. Source facts remain intact. Every correction can be undone.</p>
    <div className="flex flex-wrap gap-3">
      <label className="space-y-1">Source record<select aria-label="Source identity" className="block max-w-80 rounded border bg-background p-2" value={subject} onChange={e=>setSubject(e.target.value)}><option value="">Select a record</option>{records.map(r=><option key={r.id} value={r.id}>{r.label} · {r.id.slice(0,8)}</option>)}</select></label>
      <label className="space-y-1">Canonical record<select aria-label="Canonical identity" className="block max-w-80 rounded border bg-background p-2" value={target} onChange={e=>setTarget(e.target.value)}><option value="">Select a record</option>{records.map(r=><option key={r.id} value={r.id}>{r.label} · {r.id.slice(0,8)}</option>)}</select></label>
      <label className="space-y-1">Supporting evidence<Input aria-label="Correction reason" maxLength={512} value={reason} onChange={e=>setReason(e.target.value)} placeholder="Explain the source evidence" /></label>
    </div>
    {subject&&target&&subject!==target&&<p className="my-3">Combine {records.find(r=>r.id===subject)?.label} into {records.find(r=>r.id===target)?.label}.</p>}
    <Button className="my-3" disabled={pending||!subject||!target||subject===target||!reason.trim()} onClick={()=>void change()}>Merge records</Button>
    {error&&<p role="alert" className="text-destructive">{error}</p>}
    {!!corrections.length&&<ul className="space-y-2">{corrections.map(c=><li key={c.correction_id} className="flex flex-wrap items-center justify-between gap-2 rounded border p-2"><span>{c.reason} · {c.actor}{c.undone_at?" · Undone":""}</span>{!c.undone_at&&<Button variant="outline" size="sm" disabled={pending} onClick={()=>void change(c.correction_id)}>Undo correction</Button>}</li>)}</ul>}
  </details>;
}
