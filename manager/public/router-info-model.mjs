// Pure, presentation-only projections. Router and ISP observations are
// never mixed, and no field implies that public egress equals WAN IP.
export function routerLocalRows(state,routerIp,formatDate,info=null){
  if(!state?.compatibility)return [];
  const compat=state.compatibility;
  const line=typeof state.lineNumber==='string'?
    state.lineNumber.replace(/^\+34/,'+34.'):null;
  const whenUnknown='No disponible';
  const uptime=Number.isSafeInteger(info?.uptimeSeconds)?
    Math.floor(info.uptimeSeconds/86400)+' d · '+
      Math.floor(info.uptimeSeconds%86400/3600)+' h':null;
  return [
    ['Modelo físico del router',info?.hardwareModel||whenUnknown],
    ['Fabricante',info?.manufacturer||whenUnknown],
    ['Versión del firmware',info?.firmwareDisplay||whenUnknown],
    ['Compilación',info?.firmwareBuild||whenUnknown],
    ['Nombre local (DNS inverso y directo)',info?.localHostname||whenUnknown],
    ['IP privada del router',routerIp],
    ['ISP indicado por el Livebox',info?.routerIsp||whenUnknown],
    ['Modo WAN',info?.wanMode||whenUnknown],
    ['IPv4 WAN indicada por el Livebox',info?.wanIPv4||whenUnknown],
    ['Versión del hardware',info?.hardwareVersion||whenUnknown],
    ['Versión del cargador',info?.bootloaderVersion||whenUnknown],
    ['Tiempo desde el último arranque',uptime||whenUnknown],
    ['Línea fija',line],
    ['Última lectura de bloqueos',formatDate(state.capturedAt,true)],
    ['Compatibilidad',compat.status==='compatible'?'Comprobada':'Limitada'],
    ['Perfil del controlador',compat.profile],
    ['Bloqueos entrantes',Array.isArray(state.incoming)?state.incoming.length:null],
    ['Bloqueos salientes',Number.isInteger(state.outgoingCount)?state.outgoingCount:null],
    ['Perfiles adicionales activos',Number.isInteger(state.enabledProfiles)?state.enabledProfiles:null],
  ];
}
export function routerNetworkRows(info,formatDate){
  if(!info||info.classification!=='public-egress-not-router-wan'||
    typeof info.publicIp!=='string'||!info.publicIp)throw Error('INVALID_EGRESS_INFO');
  const approximate=[info.city,info.region,info.country].filter(Boolean).join(' · ');
  return [
    ['IP pública de salida',info.publicIp],
    ['Host público / DNS inverso',info.publicHost],
    ['Proveedor de red / operador',info.networkOperator],
    ['ASN',info.asn],
    ['Área estimada por IP',approximate||null],
    ['Zona horaria estimada',info.timezone],
    ['Fuente',info.source==='ipinfo.io'?'ipinfo.io (datos públicos)':null],
    ['Consulta',formatDate(info.fetchedAt,true)],
  ];
}
const featureDescriptors=Object.freeze([
  {label:'Historial de llamadas',modal:'Se valida al consultar',help:'Se verifica al consultar',key:null},
  {label:'Lectura de bloqueos',modal:'Disponible',help:'Disponible',key:'blockList'},
  {label:'Añadir números',modal:'Disponible',help:'Disponible',key:'add'},
  {label:'Retirar números',modal:'Disponible',help:'Disponible',key:'delete'},
  {label:'Vaciar historial',modal:'Disponible con confirmación',
    help:'Disponible con confirmación',key:'clearHistory'}
]);
export function routerFeatureRows(features,{forHelp=false}={}){
  if(!features)return [];
  return featureDescriptors.map(spec=>{
    const available=spec.key===null?null:features[spec.key]===true;
    return {label:forHelp?({
      'Historial de llamadas':'Historial de llamadas',
      'Lectura de bloqueos':'Consulta de bloqueos',
      'Añadir números':'Añadir bloqueos',
      'Retirar números':'Retirar bloqueos',
      'Vaciar historial':'Vaciar registro',
    })[spec.label]:spec.label,
      status:available===null?(forHelp?spec.help:spec.modal):
        available?(forHelp?spec.help:spec.modal):spec.label==='Lectura de bloqueos'?
          'No acreditada':'No acreditado',
      severity:available===null?'on-demand':available?'supported':'limited',
    };
  });
}
