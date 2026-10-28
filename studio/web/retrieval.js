// Present the saved retrieval trace; knowledge and ranking are never recomputed here.
const retrievalViews=[['data_flow','Data flow','Data-flow retrieval','flow'],['control_flow','Control flow','Control-flow retrieval','branch']];
const retrievalNumber=v=>typeof v==='number'&&Number.isFinite(v)?v.toFixed(3):'—';
const retrievalProject=r=>String(r.project||r.source_provenance?.repository||'Historical repair sample').replace(/^https?:\/\/(?:www\.)?github\.com\//,'').replace(/\/$/,'');
function retrievalKnowledge(record,view,raw=false){
 const saved=record.views?.[view];
 return (raw?saved?.extracted_knowledge:saved?.abstracted_knowledge)||saved||null;
}
function retrievalRecordedViews(record){return retrievalViews.filter(([view])=>record.views?.[view]);}
function retrievalModel(t=state.task||{}){
 const part=partialRetrieval(t),r=part?{...part,ranking:{candidates:part.candidates||[]},final_exemplars:[]}:t.retrieval||{},hasTrace=part?Boolean(part.completed_views?.length):Array.isArray(r.ranking?.candidates),pool=hasTrace?r.ranking.candidates:[];
 const selected=[...(part?[]:r.final_exemplars||t.exemplars||[])].sort((a,b)=>(a.selection_rank??Infinity)-(b.selection_rank??Infinity));
 const selectedIds=new Set(selected.map(c=>c.sample_id));
 const lanes=Object.fromEntries(retrievalViews.map(([view])=>[view,pool.flatMap(c=>(c.retrieval_hits||[]).filter(h=>h.query_view===view).map(hit=>({record:c,hit}))).sort((a,b)=>a.hit.rank-b.hit.rank)]));
 const total=Object.values(lanes).reduce((n,rows)=>n+rows.length,0),unique=new Set(pool.map(c=>c.sample_id)).size;
 const shared=pool.filter(c=>new Set((c.retrieval_hits||[]).map(h=>h.query_view)).size>1).length;
 return {r,partial:Boolean(part),hasTrace,pool,selected,selectedIds,lanes,total,unique,shared};
}
function retrievalSources(r){
 return (r.retrieval_hits||[]).map(h=>`<span class="retrieval-source ${esc(h.query_view)}">${h.query_view==='data_flow'?'Data flow':h.query_view==='control_flow'?'Control flow':esc(h.query_view)} <b>#${esc(h.rank)}</b></span>`).join('');
}
function retrievalRow({record:c,hit},view,m){
 const selected=m.selectedIds.has(c.sample_id),shared=new Set((c.retrieval_hits||[]).map(h=>h.query_view)).size>1;
 const opened=state.retrievalSample===c.sample_id,summary=retrievalKnowledge(c,view)?.root_cause;
 return `<li id="retrieval-row-${view}-${esc(hit.rank)}"><button class="retrieval-row ${selected?'is-selected':''} ${opened?'is-linked is-opened':''}" data-action="retrieval-example" data-sample="${esc(c.sample_id)}" data-view="${view}" aria-expanded="${opened}" aria-controls="retrieval-drawer" aria-label="${esc(c.cve_id||c.sample_id)}, ${view==='data_flow'?'Data flow':'Control flow'}rank ${esc(hit.rank)}${selected?', selected':''}">
 <span class="retrieval-rank">${esc(String(hit.rank).padStart(2,'0'))}</span><span class="retrieval-row-copy"><span class="retrieval-row-title"><strong>${esc(c.cve_id||'Historical sample')}</strong>${shared?'<span class="retrieval-shared">Both views</span>':''}</span><span class="retrieval-project" title="${esc(c.project)}">${esc(retrievalProject(c))}</span>${summary?`<span class="retrieval-row-summary">${esc(summary)}</span>`:''}<span class="retrieval-row-meta">${esc(c.language||'SOURCE')}<span title="${esc(c.sample_id)}">Sample ${esc(c.sample_id?.slice(-6))}</span></span></span>
 <span class="retrieval-row-score"><span>Distance <b>${retrievalNumber(hit.distance)}</b></span>${selected?`<span class="retrieval-chosen">${icon('check')}Selected · #${esc(c.selection_rank??'—')}</span>`:'<span class="retrieval-open">Review example →</span>'}</span></button></li>`;
}
function retrievalLane(info,m){
 const [view,label,title,glyph]=info,rows=m.lanes[view],query=m.r.queries?.[view],text=typeof query==='string'?query:query?.root_cause;
 const enabled=Boolean(query)||rows.length>0,disabled=(state.task.variant==='df_only'&&view==='control_flow')||(state.task.variant==='cf_only'&&view==='data_flow');
 const count=disabled?'Disabled':m.partial&&!m.r.completed_views?.includes(view)?'Pending':m.hasTrace?`${rows.length} examples`:Object.keys(m.r).length?'Details not saved':'Awaiting results';
 const missing=disabled?'This view was disabled for this run.':m.partial&&!m.r.completed_views?.includes(view)?'Results for this view have not arrived yet.':!m.hasTrace&&Object.keys(m.r).length?'Per-view candidate details were not saved for this run.':m.hasTrace?'No examples were retrieved from this view.':'Examples will appear in their original ranking after retrieval.';
 return `<section class="retrieval-lane ${view} ${disabled?'is-disabled':''}" aria-label="${label} Retrieved examples"><header><div class="retrieval-lane-icon">${icon(glyph)}</div><div><span class="retrieval-overline">${label}</span><h3>${title}</h3></div><span class="retrieval-lane-count">${count}</span></header>
 ${enabled?`<details class="retrieval-query"><summary>View ${title} query ${icon('chevron')}</summary><p>${esc(text||'Query text was not saved in this record.')}</p></details>`:''}
 ${rows.length?`<ol class="retrieval-results">${rows.map(row=>retrievalRow(row,view,m)).join('')}</ol>`:`<div class="retrieval-lane-empty">${icon('search')}<p>${missing}</p></div>`}</section>`;
}
function retrievalFinal(c){
 const view=c.retrieval_hits?.[0]?.query_view||'data_flow';
 const opened=state.retrievalSample===c.sample_id;
 return `<button class="retrieval-final-card ${opened?'is-linked is-opened':''}" data-action="retrieval-example" data-sample="${esc(c.sample_id)}" data-view="${esc(view)}" aria-expanded="${opened}" aria-controls="retrieval-drawer"><div class="retrieval-final-top"><span class="retrieval-final-rank">#${esc(c.selection_rank??'—')}</span><span>Combined score <b>${retrievalNumber(c.rerank_score)}</b></span>${icon('arrow')}</div>
 <h4>${esc(c.cve_id||'Historical Repair Example')}</h4><div class="retrieval-project">${esc(retrievalProject(c))}</div><div class="retrieval-source-list">${retrievalSources(c)}</div>
 <p class="retrieval-final-description">${esc(exemplarSummary(c).root_cause||c.cve_description||'View the complete repair knowledge and code diff.')}</p>
 <div class="retrieval-final-scores"><span>Code similarity <b>${retrievalNumber(c.code_cosine)}</b></span><span>Behavior relevance <b>${retrievalNumber(c.normalized_bm25)}</b></span></div></button>`;
}
function retrievalPanel(){
 const m=retrievalModel(),t=state.task;
 if(m.r.skipped||t.variant==='no_retrieval')return empty('Knowledge retrieval is disabled','Repair will use the current diagnosis report and source code.');
 const ready=m.hasTrace,summary=reportConclusion(t.diagnosis_report),protocol=m.r.ranking?.protocol||{},weighted=typeof protocol.code_weight==='number'&&typeof protocol.behavior_weight==='number';
 const counts=ready?`${m.lanes.data_flow.length} + ${m.lanes.control_flow.length}`:'—',unique=ready?m.unique:'—',chosen=ready||m.selected.length?m.selected.length:'—';
 const reviewing=Boolean(m.pool.find(c=>c.sample_id===state.retrievalSample)||m.selected.find(c=>c.sample_id===state.retrievalSample));
 return `<div class="retrieval-workspace ${reviewing?'has-retrieval-review':''}"><header class="retrieval-heading"><div><div class="label">KNOWLEDGE RETRIEVAL</div><h3>Repair Knowledge & Examples</h3></div><span class="retrieval-caption">${ready?'Retrieval trace for this run':active.includes(t.status)&&t.stage==='retrieval'?'Retrieving and reranking':m.selected.length?'Selected results for this run':'Awaiting retrieval records'}</span></header>
 <div class="retrieval-journey" aria-label="Knowledge retrieval workflow"><div><span class="retrieval-step">01</span><span><strong>Dual-view retrieval</strong><small>Data flow / Control flow</small></span><b>${counts}</b></div>${icon('arrow')}<div><span class="retrieval-step">02</span><span><strong>Merge & deduplicate</strong><small>Merge by historical sample</small></span><b>${unique}</b></div>${icon('arrow')}<div><span class="retrieval-step">03</span><span><strong>Rerank & select</strong><small>Pass to the repair agent</small></span><b>${chosen}</b></div></div>
 ${progressiveRetrievalNote(m)}${summary?`<details class="retrieval-context"><summary>${icon('file')}Diagnosis summary used for retrieval${icon('chevron')}</summary><p>${esc(summary)}</p></details>`:''}
 <nav class="retrieval-quicknav" aria-label="Retrieval navigation"><button data-action="retrieval-jump" data-target="retrieval-results">${icon('search')}Retrieved examples <span>${ready?m.total:'—'}</span></button><button data-action="retrieval-jump" data-target="retrieval-final">${icon('layers')}Selected examples <span>${chosen}</span></button><p>Select an example to inspect its knowledge and code.</p></nav>
 <div class="retrieval-review-body"><div class="retrieval-review-main">
 <div class="retrieval-section-title" id="retrieval-results" tabindex="-1"><span class="retrieval-section-number">01</span><h3>Results from Both Views</h3><span>Original ranking per view</span></div>
 <div class="retrieval-lanes">${retrievalViews.map(info=>retrievalLane(info,m)).join('')}</div>
 <section class="retrieval-merge"><div class="retrieval-merge-icon">${icon('layers')}</div><div><div class="retrieval-merge-title"><span class="retrieval-section-number">02</span><h3>Merge candidates and rerank</h3></div><p>${ready?`${m.total} hits · ${m.shared} samples found in both views · merged into <strong>${m.unique}</strong> unique candidates`:'After both views return, merge duplicate samples and calculate combined scores.'}</p><p class="retrieval-formula">${weighted?`Combined score = ${protocol.code_weight.toFixed(2)} × code similarity + ${protocol.behavior_weight.toFixed(2)} × behavior relevance`:'Rerank by code similarity and behavior relevance'}</p></div>${ready?`<span class="retrieval-merge-count">${m.unique}<span>→</span><b>${m.selected.length}</b></span>`:''}</section>
 <div class="retrieval-section-title" id="retrieval-final" tabindex="-1"><span class="retrieval-section-number">03</span><h3>Selected Repair Examples</h3><span>${m.selected.length?`${m.selected.length} examples · ordered by rerank score`:'Awaiting selected examples'}</span></div>
 ${m.selected.length?`<div class="retrieval-final-grid">${m.selected.map(retrievalFinal).join('')}</div>`:`<div class="retrieval-final-empty">${icon('layers')}<p>${m.partial?'Reranking candidates. Selected examples will appear when complete.':ready?'No repair examples were available for selection in this run.':'Selected repair examples will appear after reranking.'}</p></div>`}</div>${renderRetrievalDrawer(m)}</div></div>`;
}
function openRetrievalExample(sampleId,view){
 const m=retrievalModel(),record=m.pool.find(c=>c.sample_id===sampleId)||m.selected.find(c=>c.sample_id===sampleId);
 if(!record)return;
 const recorded=retrievalRecordedViews(record).map(([v])=>v);
 state.retrievalSample=sampleId;state.retrievalView=recorded.includes(view)?view:recorded[0]||view||'data_flow';render();
}
function closeRetrievalExample(){state.retrievalSample=null;render();}
function setRetrievalView(view){
 const m=retrievalModel(),record=m.pool.find(c=>c.sample_id===state.retrievalSample)||m.selected.find(c=>c.sample_id===state.retrievalSample);
 if(record?.views?.[view]){state.retrievalView=view;render();}
}
function retrievalDrawerCode(record){
 const sources=[['buggy_code','Vulnerable source'],['fixed_code','Patched source']].filter(([key])=>typeof record[key]==='string'&&record[key]);
 return `<section class="retrieval-drawer-section"><h4>Historical Diff</h4>${record.patch?diffView(record.patch):'<p class="muted-note">No patch diff was saved in this record.</p>'}${sources.map(([key,title])=>`<details class="retrieval-code-source" data-reading-key="retrieval-${key}"><summary>${esc(title)}${icon('chevron')}</summary><pre class="retrieval-source-code" tabindex="0">${esc(record[key])}</pre></details>`).join('')}</section>`;
}
function renderRetrievalDrawer(m){
 const record=m.pool.find(c=>c.sample_id===state.retrievalSample)||m.selected.find(c=>c.sample_id===state.retrievalSample);if(!record)return '';
 const views=retrievalRecordedViews(record),view=views.some(([v])=>v===state.retrievalView)?state.retrievalView:views[0]?.[0]||state.retrievalView;
 const knowledge=retrievalKnowledge(record,view),raw=record.views?.[view]?.extracted_knowledge,selected=m.selectedIds.has(record.sample_id);
 return `<aside class="retrieval-drawer" id="retrieval-drawer" role="complementary" aria-labelledby="retrieval-drawer-title" tabindex="-1" data-ui-key="retrieval-drawer"><header class="retrieval-drawer-heading"><div><span class="label">Historical Repair Example</span><h3 id="retrieval-drawer-title">${esc(record.cve_id||'Historical repair sample')}</h3></div><button class="retrieval-drawer-close" data-action="retrieval-close" aria-label="Close example review">${icon('close')}</button></header>
 <div class="retrieval-drawer-scroll" data-preserve-scroll="retrieval-drawer" data-ui-key="retrieval-drawer-scroll"><div class="retrieval-drawer-meta"><span>${esc(retrievalProject(record))}</span>${pill(record.language||'SOURCE')}${pill(selected?'Selected':'Candidate',selected?'teal':'')}</div>
 <section class="retrieval-drawer-trace"><h4>Retrieval Trace</h4><div class="retrieval-origin-list">${(record.retrieval_hits||[]).map(h=>`<button data-action="retrieval-origin" data-sample="${esc(record.sample_id)}" data-view="${esc(h.query_view)}" data-rank="${esc(h.rank)}" title="Locate the original ranking in this view"><span>${h.query_view==='data_flow'?'Data flow':h.query_view==='control_flow'?'Control flow':esc(h.query_view)} <b>#${esc(h.rank)}</b></span><span>Distance ${retrievalNumber(h.distance)} ${icon('arrow')}</span></button>`).join('')||'<p class="muted-note">Per-view retrieval details were not saved in this record.</p>'}</div><dl class="retrieval-drawer-scores"><div><dt>Rerank position</dt><dd>#${esc(record.selection_rank??'—')}</dd></div><div><dt>Combined score</dt><dd>${retrievalNumber(record.rerank_score)}</dd></div><div><dt>Code similarity</dt><dd>${retrievalNumber(record.code_cosine)}</dd></div><div><dt>Behavior relevance</dt><dd>${retrievalNumber(record.normalized_bm25)}</dd></div></dl></section>
 ${views.length?`<div class="retrieval-drawer-tabs" role="group" aria-label="Historical knowledge views">${views.map(([v,label])=>`<button class="${view===v?'active':''}" data-action="retrieval-view" data-view="${v}" aria-pressed="${view===v}">${label}</button>`).join('')}</div>`:''}
 <section class="retrieval-drawer-section retrieval-drawer-knowledge"><h4>${view==='control_flow'?'Control flow':'Data flow'}Repair Knowledge</h4>${fields(knowledge)}${raw?`<details class="retrieval-raw-knowledge" data-reading-key="retrieval-raw-${esc(view)}"><summary>Original extracted knowledge${icon('chevron')}</summary>${fields(raw)}</details>`:''}</section>
 ${record.cve_description?`<details class="retrieval-description" data-reading-key="retrieval-description"><summary>Vulnerability description${icon('chevron')}</summary><p>${esc(record.cve_description)}</p></details>`:''}${retrievalDrawerCode(record)}
 <div class="retrieval-drawer-foot">Sample <span>${esc(record.sample_id)}</span></div></div></aside>`;
}
function retrievalEvidence(r){
 if(!r.retrieval_hits?.length)return '';
 const selected=retrievalModel().selectedIds.has(r.sample_id);
 return `<section class="retrieval-evidence"><div class="section-head"><strong>Retrieval Trace</strong>${pill(selected?'Selected':'Not selected',selected?'teal':'')}</div><div class="retrieval-evidence-hits">${r.retrieval_hits.map(h=>`<div>${retrievalSources({retrieval_hits:[h]})}<span>Retrieval distance <b>${retrievalNumber(h.distance)}</b></span></div>`).join('')}</div><div class="retrieval-evidence-scores"><span>Rerank position <b>#${esc(r.selection_rank??'—')}</b></span><span>Code similarity <b>${retrievalNumber(r.code_cosine)}</b></span><span>Behavior relevance <b>${retrievalNumber(r.normalized_bm25)}</b></span><span>Combined score <b>${retrievalNumber(r.rerank_score)}</b></span></div><small>Sample ${esc(r.sample_id?.slice(-12))} · Behavior relevance uses normalized BM25 scores</small></section>`;
}
// Link the same sample across both retrieval lanes and the final selection.
function highlightRetrievalSample(sample){
 const selected=state.retrievalSample;
 document.querySelectorAll('.retrieval-workspace .retrieval-row,.retrieval-workspace .retrieval-final-card').forEach(el=>el.classList.toggle('is-linked',Boolean(sample)&&el.dataset.sample===sample||Boolean(selected)&&el.dataset.sample===selected));
}
document.addEventListener('mouseover',e=>{const row=e.target.closest('.retrieval-workspace [data-sample]');if(row)highlightRetrievalSample(row.dataset.sample);});
document.addEventListener('mouseout',e=>{const row=e.target.closest('.retrieval-workspace [data-sample]');if(row&&!row.contains(e.relatedTarget))highlightRetrievalSample(null);});
document.addEventListener('focusin',e=>{const row=e.target.closest('.retrieval-workspace [data-sample]');if(row)highlightRetrievalSample(row.dataset.sample);});
document.addEventListener('focusout',e=>{if(e.target.closest('.retrieval-workspace [data-sample]'))highlightRetrievalSample(null);});
