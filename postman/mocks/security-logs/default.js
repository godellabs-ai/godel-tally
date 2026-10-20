// Contract fixtures; setup and evidence scope: https://godel-labs.ai/docs/tally/connectors#security-sources.
const http = require('node:http');
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const reply = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  const auth = req.headers['netskope-api-token'] || req.headers['x-api-key'];
  if (auth === 'unauthorized') return reply(401, { message: 'Unauthorized' });
  if (auth === 'rate-limited') { res.setHeader('Retry-After', '60'); return reply(429, { message: 'API rate limit exceeded' }); }
  if (auth === 'unavailable') return reply(503, { message: 'Service unavailable' });
  if (auth !== 'fixture-key') return reply(403, { message: 'Missing fixture API credential' });
  if (url.pathname.startsWith('/log_search/query/')) {
    if (url.pathname.endsWith('/pending')) {
      return reply(200, { events: [{ message: JSON.stringify({ timestamp: '2026-10-17T05:00:00Z', entry_id: 'rapid7-1', query: 'api.openai.com', asset: 'laptop-42', user: 'analyst@example.test', observation_count: 2, query_blocked: 'false', source_data: 'PRIVATE_SOURCE_CANARY' }), timestamp: 1792213200000, sequence_number: 1 }], links: [{rel: 'Next', href: '/log_search/query/logs/00000000-0000-0000-0000-000000000001?from=1792213200000&to=1792213259999&per_page=500&next_page=true'}] });
    }
    if (url.searchParams.get('next_page') === 'true') return reply(200, {events: [], links: []});
    if (url.searchParams.get('per_page') !== '500' || url.searchParams.get('to') !== '1792213259999') return reply(400, { message: 'Incorrect bounded query' });
    return reply(202, {events: [], links: [{rel: 'Self', href: '/log_search/query/pending'}]});
  }
  if (url.pathname === '/api/v2/events/data/page' || url.pathname === '/api/v2/events/data/application') {
    if (url.searchParams.get('starttime') !== '1792213200' || url.searchParams.get('endtime') !== '1792213259' || url.searchParams.get('limit') !== '500') return reply(400, { message: 'Incorrect bounded query' });
    const offset = Number(url.searchParams.get('offset'));
    return reply(200, {ok: 1, result: offset === 0 ? Array.from({length: 500}, (_, i) => ({_id: `netskope-${i}`, timestamp: 1792213200, url: 'https://api.openai.com/v1/responses?prompt=PRIVATE_PAYLOAD_CANARY', user: 'analyst@example.test', hostname: 'laptop-42', nsdeviceuid: 'device-1', srcip: '10.0.0.8', action: 'allow', count: 1, object: 'PRIVATE_FILE_CANARY'})) : []});
  }
  reply(501, { message: 'Endpoint not covered by this contract fixture' });
}).listen(process.env.PORT || 4909, '127.0.0.1');
