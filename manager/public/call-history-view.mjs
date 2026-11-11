import {
  queryHistory,groupHistory,validateHistoryRange,counterpart,isBlockable,
  CALL_LABELS,CALL_ICONS,BLOCK_ICON
} from './history-view.mjs';
import {classifyTelephone,provinceForPhoneNumber} from './call-enrichment.mjs';

// History presentation only. Actual calls, confirmations, data and the
// single-dispatch Livebox guards remain in their existing controllers.
export function setupCallHistoryView({
  ui,model,make,text,actionIcon,setActionButton,
  running,dateLabel,canWrite,preparePlan,notice
}){
  function resetHistoryFilters() {
    model.historyPage=0;
    ui.historySearch.value=''; ui.historyType.value='ALL'; ui.historyPeriod.value='all';
    ui.historyFrom.value='';ui.historyTo.value='';ui.historySort.value='date-desc';ui.historyGroup.value='date';
  }
  function renderCallHistory() {
    const fetching=model.pending==='call-history';
    ui.historyLoadButton.disabled=!model.authenticated||!!model.pending||running()||model.disconnectFailed;
    setActionButton(ui.historyLoadButton,fetching?'Cargando llamadas…':model.callHistory?'Actualizar llamadas':'Consultar llamadas','refresh');
    ui.historyPanel.setAttribute('aria-busy',fetching?'true':'false');
    text(ui.historyError,model.historyError);ui.historyError.hidden=!model.historyError;
    ui.historyDates.hidden=ui.historyPeriod.value!=='custom';
    const all=model.callHistory?.calls||[];
    text(ui.missedCount,model.callHistory?all.filter(c=>ui.historyType.value==='ALL'||c.type===ui.historyType.value).length:'—');
    // Keep the heading descriptive when switching away from the default missed view.
    const heading=ui.historyTitle.firstChild;
    if(heading?.nodeType===Node.TEXT_NODE) heading.textContent=ui.historyType.value==='MISS'?'Llamadas perdidas ':'Historial de llamadas ';
    const rows=queryHistory(all,{type:ui.historyType.value,search:ui.historySearch.value,
      period:ui.historyPeriod.value,from:ui.historyFrom.value,to:ui.historyTo.value,sort:ui.historySort.value});
    const invalidDates=ui.historyPeriod.value==='custom' ? (ui.historyFrom.validity.badInput || ui.historyTo.validity.badInput ? 'Introduce fechas válidas para el intervalo personalizado.' : validateHistoryRange(ui.historyFrom.value,ui.historyTo.value)) : '';
    const groups = groupHistory(rows,ui.historyGroup.value,ui.historySort.value);
    const pages = Math.max(1,Math.ceil(rows.length/100));
    model.historyPage = Math.max(0,Math.min(model.historyPage,pages-1));
    const first = model.historyPage*100, last = Math.min(first+100,rows.length);
    ui.historyPager.hidden = !model.authenticated || rows.length<=100;
    ui.historyPrevious.disabled = model.historyPage===0;
    ui.historyNext.disabled = model.historyPage>=pages-1;
    text(ui.historyPageStatus,`Página ${model.historyPage+1} de ${pages} · llamadas ${rows.length?first+1:0}–${last} de ${rows.length}`);
    text(ui.historyStatus,fetching?'Consultando las llamadas de tu Livebox…':invalidDates?invalidDates:
      !model.callHistory?(model.authenticated&&model.legacy?'Historial no disponible en esta lectura. Puedes volver a consultarlo.':'El historial se cargará al iniciar sesión.'):
      model.callHistory.total===0?'El Livebox no ha devuelto llamadas en esta consulta. Esto no demuestra que el historial anterior se haya borrado.':
      rows.length===0?'No hay llamadas que coincidan con los filtros.':
      rows.length+' llamadas coinciden · '+all.length+' disponibles'+(model.callHistory.truncated||model.callHistory.total>all.length?' de '+model.callHistory.total+' (historial recibido truncado)':'')+' · consulta de '+dateLabel(model.callHistory.capturedAt,true)+'.');
    ui.historyList.hidden=!model.authenticated||rows.length===0;
    const fragment=document.createDocumentFragment();
    let preceding=0;
    for(const fullGroup of groups) {
      const start=Math.max(0,first-preceding),end=Math.min(fullGroup.calls.length,last-preceding);
      preceding+=fullGroup.calls.length;
      if(end<=start)continue;
      const group={...fullGroup,calls:fullGroup.calls.slice(start,end)};
      if(group.label) {
        const header=make('li','history-group');
        const heading=make('span','history-group-title');
        heading.append(make('span','',group.label));
        if(ui.historyGroup.value==='number'){
          const place=provinceForPhoneNumber(group.key);
          if(place){
            const province=make('span','history-group-province','('+place+')');
            province.title='Provincia asociada al prefijo, no ubicación física del llamante';
            heading.append(province);
          }
          if(classifyTelephone(group.key).kind==='commercial'){
            const advert=make('span','history-group-advertising','(Publicidad)');
            advert.title='Numeración comercial 400 (BOE-A-2026-8409)';
            heading.append(advert);
          }
        }
        header.append(heading,make('span','history-group-count',fullGroup.calls.length+' '+(fullGroup.calls.length===1?'llamada':'llamadas')));
        fragment.append(header);
      }
      for(const item of group.calls) {
        const number=counterpart(item);
        const row=make('li','call-history-row');row.dataset.callType=item.type;
        const icon=make('span','call-type-icon type-'+item.type);icon.innerHTML=CALL_ICONS[item.type]||CALL_ICONS.IN;
        const identity=make('div','call-history-identity');
        const numberLine=make('div','call-history-number-line');
        numberLine.append(make('span','call-history-number',number));
        const provinceName=provinceForPhoneNumber(number);
        if(provinceName){
          const province=make('span','call-province','('+provinceName+')');
          province.title='Provincia correspondiente al prefijo del número; no confirma la ubicación del llamante';
          numberLine.append(province);
        }
        const category=classifyTelephone(number);
        if(category.kind==='mobile'){
          const marker=make('span','call-number-indicator mobile-indicator');
          marker.append(actionIcon('mobile'));
          marker.title=category.label;marker.setAttribute('aria-label',category.label);
          numberLine.append(marker);
        }else if(category.kind==='international'||category.kind==='unknownInternational'){
          const marker=make('span','call-number-indicator country-indicator');
          marker.setAttribute('title',category.label);
          marker.setAttribute('aria-label',category.label);
          if(category.iso){
            const flag=document.createElement('img');
            flag.className='country-flag';flag.alt='';
            flag.loading='lazy';flag.decoding='async';
            flag.src='/flags/'+category.iso+'.svg';
            flag.addEventListener('error',()=>{flag.remove();text(marker,category.flag);},{once:true});
            marker.append(flag);
          }else text(marker,category.flag);
          numberLine.append(marker);
        }
        const automaticAdvertising=category.kind==='commercial';
        const tagged=model.advertisingNumbers.has(number);
        if(automaticAdvertising||tagged){
          const marker=make('span','call-number-indicator advertising-indicator');
          marker.append(actionIcon('megaphone'));
          if(automaticAdvertising){
            marker.append(make('span','advertising-prefix-label','(Publicidad)'));
            marker.title='Numeración comercial española 400';
          }else marker.title='Publicidad (marcado manualmente)';
          marker.setAttribute('aria-label',marker.title);
          numberLine.append(marker);
        }
        identity.append(numberLine,make('p','call-history-metadata',CALL_LABELS[item.type]+' · '+item.dateTime+' · '+item.duration));
        const button=make('button','history-block-button');button.type='button';button.innerHTML=BLOCK_ICON;
        const already=model.state?.incoming.some(rule=>rule.pattern===number);
        const capable=isBlockable(item);
        const label=already?'Este número ya está bloqueado':!capable?'Este identificador no admite bloqueo literal sin conversión':'Bloquear llamadas entrantes de '+number;
        button.title=label;button.dataset.callNumber=number;button.setAttribute('aria-label',label);
        button.disabled=!!already||!capable||!canWrite('add');
        if(already)button.classList.add('is-blocked');
        button.append(make('span','sr-only',label));
        button.addEventListener('click',()=>{if(canWrite('add')&&capable&&!model.state.incoming.some(rule=>rule.pattern===number))preparePlan({type:'add',pattern:number},button);});
        if(item.type!=='OUT'&&number&&!automaticAdvertising){
          const ad=make('button','history-ad-button'+(tagged?' is-advertising':''));
          ad.type='button';ad.append(actionIcon('megaphone'));
          const caption=tagged?'Quitar etiqueta de publicidad':'Marcar como publicidad';
          ad.title=caption;ad.setAttribute('aria-label',caption+' · '+number);
          ad.setAttribute('aria-pressed',tagged?'true':'false');
          ad.append(make('span','sr-only',caption));
          ad.addEventListener('click',()=>{
            if(!model.authenticated)return;
            if(model.advertisingNumbers.has(number))model.advertisingNumbers.delete(number);
            else model.advertisingNumbers.add(number);
            renderCallHistory();
            notice(model.advertisingNumbers.has(number)?
              'Número marcado como publicidad durante esta sesión.':
              'Se ha quitado la etiqueta de publicidad.','success');
          });
          row.append(icon,identity,ad);
        }else row.append(icon,identity);
        if(model.legacy){button.disabled=true;button.title='Bloqueo no disponible en este firmware';button.setAttribute('aria-label',button.title);}
        row.append(button);
        fragment.append(row);
      }
    }
    ui.historyList.replaceChildren(fragment);
  }
  return {resetHistoryFilters,renderCallHistory};
}
