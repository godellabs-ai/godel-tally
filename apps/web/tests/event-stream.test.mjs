import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sourceModule } from './source-module.mjs';
const { authorizationReason, eventActivity, eventHandoff, eventPerson, eventStatus } = sourceModule('lib/event-stream.ts');
const base = { event: { observation_id: 'event-1', kind: 'http_metadata', observed_at: '2026-10-16T10:00:00Z', received_at: '2026-10-16T10:01:00Z', connector: {instance_id:'source',connector_type:'gateway'}, actor: { identity: { subject_key: 'hashed-identity' }, source_ip: '10.0.0.1' }, outcome: {action:'allowed'} }, connector:'Gateway', findings:[] };
const finding = (status, provider, model = null) => ({ observation_id:'event-1', finding_id:status, status, evidence_kind:'ai_usage', provider:{name:'Provider',sanctioned:provider}, model });
test('mixed decisions expose the rejected model, independently of an allowed source outcome', () => {
  const row = {...base, findings:[finding('sanctioned',true),finding('unsanctioned',true,{name:'Restricted model',sanctioned:false})]};
  assert.equal(eventStatus(row),'unsanctioned');
  assert.equal(authorizationReason(row),'Restricted model is marked unsanctioned in AI Registry.');
  assert.match(eventHandoff(row),/Source action: allowed/);
  assert.match(eventHandoff(row),/Authorization: Unsanctioned/);
});
test('missing links and pseudonymous identities remain explicitly unresolved', () => {
  assert.equal(eventStatus(base),'authorization_queue');
  assert.equal(eventPerson(base.event),undefined);
  assert.match(eventHandoff(base),/Person: Not identified by source/);
  assert.match(eventHandoff(base),/Observed: \d{1,2}(st|nd|rd|th) Oct 2026, \d\d:\d\d:\d\d \(2026-10-16T10:00:00Z\)/);
  assert.doesNotMatch(eventHandoff(base),/hashed-identity/);
});
test('resource discovery and passive traffic do not become requests merely because a provider is known', () => {
  assert.equal(eventActivity(base),'HTTP activity');
  assert.equal(eventActivity({...base,findings:[finding('sanctioned',true)],event:{...base.event,kind:'cloud_resource'}}),'Resource discovered');
  assert.equal(eventActivity({...base,findings:[finding('sanctioned',true)]}),'AI request');
});
