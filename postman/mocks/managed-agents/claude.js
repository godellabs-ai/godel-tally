// Read-only contract fixture; setup and evidence scope: https://godel-labs.ai/docs/tally/connectors#attribution.
const http = require('node:http');
const provider = 'claude';
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://fixture.local');
  const send = (status, body) => { res.writeHead(status, {'Content-Type':'application/json'}); res.end(JSON.stringify(body)); };
  const key = provider === 'openai' ? req.headers.authorization?.replace('Bearer ', '') : req.headers[provider === 'claude' ? 'x-api-key' : 'x-goog-api-key'];
  const path = provider === 'gemini' ? '/v1beta/agents' : '/v1/agents';
  if (req.method !== 'GET' || url.pathname !== path) return send(501, {error:'Endpoint not defined'});
  if (['fixture-401','fixture-403','fixture-429','fixture-500'].includes(key)) return send(Number(key.slice(8)), {error:{message:'CONTENT_CANARY'}});
  if (key === 'fixture-invalid-json') { res.writeHead(200, {'Content-Type':'text/html'}); return res.end('<html>CONTENT_CANARY</html>'); }
  if (!['fixture-key','fixture-empty'].includes(key)) return send(401, {error:'Unexpected fixture credential'});
  const expected = provider === 'openai' ? {'openai-beta':'agents=v1','openai-project':'proj_test'} : provider === 'claude' ? {'anthropic-version':'2023-06-01','anthropic-beta':'managed-agents-2026-04-01','anthropic-workspace-id':'wrkspc_test'} : {};
  for (const [name,value] of Object.entries(expected)) if (req.headers[name] !== value) return send(400, {error:'Missing provider header: '+name});
  const sizeKey = provider === 'gemini' ? 'page_size' : 'limit';
  if (url.searchParams.get(sizeKey) !== '100') return send(400, {error:'Incorrect page size'});
  if (provider === 'openai' && url.searchParams.get('order') !== 'asc') return send(400,{error:'Incorrect order'});
  if (provider === 'claude' && url.searchParams.get('include_archived') !== 'true') return send(400,{error:'Missing archived records'});
  if (provider === 'gemini' && url.searchParams.get('parent') !== 'projects/test/locations/global') return send(400,{error:'Incorrect parent'});
  const cursorKey = provider === 'openai' ? 'after' : provider === 'claude' ? 'page' : 'page_token';
  const cursor = url.searchParams.get(cursorKey);
  const next = provider === 'openai' ? 'agent_1' : 'opaque+/=page2';
  if (cursor && cursor !== next) return send(400,{error:'Incorrect cursor'});
  const suffix = cursor ? '2' : '1';
  let record = {id:'agent_'+suffix,name:'Research '+suffix,model:'gpt-5',instructions:'CONTENT_CANARY',metadata:{secret:'CONTENT_CANARY'},tools:[{headers:{Authorization:'CONTENT_CANARY'}}]};
  if (provider === 'claude') record = {...record,model:{id:'claude-sonnet-4-6',effort:{type:'low'}},system:'CONTENT_CANARY',archived_at:cursor ? '2026-10-15T00:00:00Z' : null};
  if (provider === 'gemini') record = {id:'research-'+suffix,display_name:'Research '+suffix,agent_config:{model:'gemini-2.5-pro'},system_instruction:'CONTENT_CANARY',base_environment:{env:{TOKEN:'CONTENT_CANARY'}}};
  const records = key === 'fixture-empty' ? [] : [record];
  const more = records.length > 0 && !cursor;
  if (provider === 'openai') return send(200,{object:'list',data:records,has_more:more,last_id:records.length ? record.id : null});
  if (provider === 'claude') return send(200,{data:records,next_page:more ? next : null});
  return send(200, records.length ? {agents:records,...(more ? {next_page_token:next} : {})} : {});
}).listen(process.env.PORT);
