// Bounded local-only presentation. Never modifies a telephone identifier
// used for sorting, matching, the call log, or router blocking commands.
// Country prefixes follow ITU E.164; unknown/shared codes are NOT assigned
// an invented national flag.
const countryData=Object.freeze([
 ['351','Portugal','🇵🇹'],['352','Luxemburgo','🇱🇺'],['353','Irlanda','🇮🇪'],
 ['354','Islandia','🇮🇸'],['355','Albania','🇦🇱'],['356','Malta','🇲🇹'],['357','Chipre','🇨🇾'],
 ['358','Finlandia','🇫🇮'],['359','Bulgaria','🇧🇬'],['370','Lituania','🇱🇹'],
 ['371','Letonia','🇱🇻'],['372','Estonia','🇪🇪'],['373','Moldavia','🇲🇩'],
 ['374','Armenia','🇦🇲'],['375','Bielorrusia','🇧🇾'],['376','Andorra','🇦🇩'],
 ['377','Mónaco','🇲🇨'],['378','San Marino','🇸🇲'],['380','Ucrania','🇺🇦'],
 ['381','Serbia','🇷🇸'],['382','Montenegro','🇲🇪'],['383','Kosovo','🇽🇰'],
 ['385','Croacia','🇭🇷'],['386','Eslovenia','🇸🇮'],['387','Bosnia y Herzegovina','🇧🇦'],
 ['389','Macedonia del Norte','🇲🇰'],['420','Chequia','🇨🇿'],['421','Eslovaquia','🇸🇰'],
 ['423','Liechtenstein','🇱🇮'],['350','Gibraltar','🇬🇮'],['30','Grecia','🇬🇷'],
 ['31','Países Bajos','🇳🇱'],['32','Bélgica','🇧🇪'],['33','Francia','🇫🇷'],
 ['34','España','🇪🇸'],['36','Hungría','🇭🇺'],['39','Italia','🇮🇹'],
 ['40','Rumanía','🇷🇴'],['41','Suiza','🇨🇭'],['43','Austria','🇦🇹'],
 ['44','Reino Unido','🇬🇧'],['45','Dinamarca','🇩🇰'],['46','Suecia','🇸🇪'],
 ['47','Noruega','🇳🇴'],['48','Polonia','🇵🇱'],['49','Alemania','🇩🇪'],
 ['52','México','🇲🇽'],['53','Cuba','🇨🇺'],['54','Argentina','🇦🇷'],
 ['55','Brasil','🇧🇷'],['56','Chile','🇨🇱'],['57','Colombia','🇨🇴'],
 ['58','Venezuela','🇻🇪'],['51','Perú','🇵🇪'],['593','Ecuador','🇪🇨'],
 ['595','Paraguay','🇵🇾'],['598','Uruguay','🇺🇾'],
 ['212','Marruecos','🇲🇦'],['213','Argelia','🇩🇿'],['216','Túnez','🇹🇳'],
 ['221','Senegal','🇸🇳'],['234','Nigeria','🇳🇬'],['27','Sudáfrica','🇿🇦'],
 ['20','Egipto','🇪🇬'],['90','Turquía','🇹🇷'],['91','India','🇮🇳'],
 ['92','Pakistán','🇵🇰'],['94','Sri Lanka','🇱🇰'],['98','Irán','🇮🇷'],
 ['81','Japón','🇯🇵'],['82','Corea del Sur','🇰🇷'],['84','Vietnam','🇻🇳'],
 ['86','China','🇨🇳'],['852','Hong Kong','🇭🇰'],['853','Macao','🇲🇴'],
 ['886','Taiwán','🇹🇼'],['61','Australia','🇦🇺'],['64','Nueva Zelanda','🇳🇿'],
 ['62','Indonesia','🇮🇩'],['63','Filipinas','🇵🇭'],['65','Singapur','🇸🇬'],
 ['66','Tailandia','🇹🇭'],['971','Emiratos Árabes Unidos','🇦🇪'],
 ['972','Israel','🇮🇱'],['966','Arabia Saudí','🇸🇦'],
 ['1','Código +1 (varios países)','🌐'],['7','Código +7 (varios países)','🌐']
].sort((a,b)=>b[0].length-a[0].length));

function regionalIso(flag) {
  const codepoints=[...flag].map(character=>character.codePointAt(0));
  if(codepoints.length!==2||!codepoints.every(x=>x>=0x1F1E6&&x<=0x1F1FF))return null;
  return codepoints.map(x=>String.fromCharCode(97+x-0x1F1E6)).join('');
}
export const FLAG_ISOS = new Set(countryData.map(item=>regionalIso(item[2])).filter(Boolean));

const spanishMobile = n => /^6[0-9]{8}$/.test(n)||/^7[1-4][0-9]{7}$/.test(n);
// BOE-A-2026-8409: Spanish NXY=400, exactly nine national digits.
// Only presentation is enriched. Original call and block identifiers remain untouched.
export function commercial400NationalNumber(raw){
 if(typeof raw!=='string')return null;
 if(/^400\d{6}$/.test(raw))return raw;
 for(const re of [/^\+34(400\d{6})$/,/^0034(400\d{6})$/,/^34(400\d{6})$/]){
   const match=re.exec(raw);
   if(match)return match[1];
 }
 return null;
}
export function classifyTelephone(raw){
 if(commercial400NationalNumber(raw))return {kind:'commercial',label:'Publicidad',flag:null};
 const value=typeof raw==='string'?raw:'';
 const normalized=/^\+[0-9]{5,15}$/.test(value)?value.slice(1):
   /^00[0-9]{5,15}$/.test(value)?value.slice(2):null;
 if(normalized){
   const country=countryData.find(([code])=>normalized.startsWith(code)&&
     normalized.length-code.length>=4);
   if(!country)return {kind:'unknownInternational',label:'Prefijo internacional no identificado',flag:'🌐'};
   const [code,name,flag]=country;
   if(code==='34'){
     const local=normalized.slice(2);
     return spanishMobile(local)?{kind:'mobile',label:'Móvil español',flag:null}:
       {kind:'national',label:'España',flag:null};
   }
   return {kind:'international',code,country:name,flag,iso:regionalIso(flag),label:'Llamada internacional · '+name};
 }
 if(spanishMobile(value))return {kind:'mobile',label:'Móvil español',flag:null};
 return {kind:'other',label:null,flag:null};
}
export const callIdentity=call=>JSON.stringify([
 call?.type,call?.dateTime,call?.duration,call?.source,call?.destination
]);
// Stable multiset difference: two equal records are two calls. Always exclude
// outbound calls from "received call" notifications.
export function newlyRecordedInbound(previous,current){
 if(!Array.isArray(previous)||!Array.isArray(current))return [];
 const counter=new Map();
 for(const call of previous){
   const key=callIdentity(call);
   counter.set(key,(counter.get(key)||0)+1);
 }
 const incoming=[];
 for(const call of current){
   const key=callIdentity(call),old=counter.get(key)||0;
   if(old>0){counter.set(key,old-1);continue;}
   if(call?.type==='IN'||call?.type==='MISS')incoming.push(call);
 }
 return incoming;
}


// Province-by-numbering-zone lookup; presentation only, no router writes.
//
// Official references:
// - Spain's E.164 national numbering allocation (province ranges 8/9):
//   https://digital.gob.es/content/dam/portal-mtdfp/avance-digital/telecomunicacion-e-infraestructuras-digitales/servicios/numeracion/documents/presentacion_pnn_espana.pdf
// - BOE-A-2026-9431, annexes II/III (updated 8XY allocations):
//   https://www.boe.es/diario_boe/txt.php?id=BOE-A-2026-9431
//
// National geographic numbers consist of EXACTLY nine digits. Classification
// refers to the numbering area, NOT the caller's physical location or identity.
// For some 8XY allocations the FOURTH national digit is constrained by BOE:
// do not identify reserved subranges as though they were allocated.
//
// Strictly no normalization of the identifier passed to the block/deny API.

export const PROVINCE_PREFIX_REFERENCE='BOE-A-2026-9431 + PNN E.164 2021-02-18';

// A full 3-digit NXY prefix has a single zone.
// In this list the 9XY ranges are used in the 2021 ministerial PNN.
const provinces = Object.freeze([
  ['Madrid','910 911 912 913 914 915 916 917 918 919 810 815'],
  ['Barcelona','930 931 932 933 934 935 936 937 938 830'],
  ['Ávila','920 820'],
  ['Segovia','921 821'],
  ['Santa Cruz de Tenerife','922 822'],
  ['Salamanca','923 823'],
  ['Badajoz','924 824'],
  ['Toledo','925 825'],
  ['Ciudad Real','926 826'],
  ['Cáceres','927 827'],
  ['Las Palmas','928 828'],
  ['La Rioja','941 841'],
  ['Cantabria','942 842'],
  ['Guipúzcoa','943 843'],
  ['Vizcaya','944 946 846'],
  ['Álava','945 845'],
  ['Burgos','947 847'],
  ['Navarra','948 848'],
  ['Guadalajara','949 849'],
  ['Almería','950 850'],
  ['Málaga','951 952 851'],
  ['Jaén','953 853'],
  ['Sevilla','954 955 854'],
  ['Cádiz','956 856'],
  ['Córdoba','957 857'],
  ['Granada','958 858'],
  ['Huelva','959 859'],
  ['Valencia','960 961 962 963 860'],
  ['Castellón','964 864'],
  ['Alicante','965 966 865'],
  ['Albacete','967 867'],
  ['Murcia','968 868'],
  ['Cuenca','969 869'],
  ['Islas Baleares','971 871'],
  ['Gerona','972 872'],
  ['Lérida','973 873'],
  ['Huesca','974 874'],
  ['Soria','975 875'],
  ['Zaragoza','976 876'],
  ['Tarragona','977 877'],
  ['Teruel','978 878'],
  ['Palencia','979 879'],
  ['Zamora','980 880'],
  ['A Coruña','981 881'],
  ['Lugo','982 882'],
  ['Valladolid','983 883'],
  ['Asturias','984 985 884'],
  ['Pontevedra','986 886'],
  ['León','987 887'],
  ['Ourense','988 888']
]);

const prefixToProvince = new Map();
for (const [province, text] of provinces) {
  for (const prefix of text.split(' ')) {
    if(prefixToProvince.has(prefix))throw Error('Duplicate geographic prefix');
    prefixToProvince.set(prefix,province);
  }
}

// Per BOE-A-2026-9431, Annex II and III. No entry means no 8XY
// allocation known to this table. "all" denotes all fourth digits.
const allowedFourth = Object.freeze({
  '810':'all','815':'all',
  '820':'0','821':'0','822':'01234679','823':'0',
  '824':'069','825':'0789','826':'09','827':'09',
  '828':'0126789','830':'all',
  '841':'0','842':'089','843':'069','845':'0',
  '846':'016789','847':'0','848':'04689','849':'0',
  '850':'09','851':'01','853':'089','854':'0156789',
  '856':'all','857':'06789','858':'0126789','859':'09',
  '860':'01','864':'089','865':'0156789','867':'09',
  '868':'all','869':'0',
  '871':'all','872':'01245679','873':'0469',
  '874':'0','875':'0','876':'all','877':'0124689',
  '878':'0','879':'0','880':'0','881':'all',
  '882':'0','883':'089','884':'01','886':'012345679',
  '887':'089','888':'0'
});

export const GEOGRAPHIC_PROVINCE_COUNT = provinces.length;
export const GEOGRAPHIC_PREFIX_COUNT = prefixToProvince.size;

/** Accept national, +34, 0034 or explicit 34+national forms; never alter input. */
export function geographicNationalNumber(raw){
  if(typeof raw!=='string')return null;
  if(/^[89]\d{8}$/.test(raw))return raw;
  const matches=[/^\+34([89]\d{8})$/,/^0034([89]\d{8})$/,/^34([89]\d{8})$/];
  for(const re of matches){
    const found=re.exec(raw);
    if(found)return found[1];
  }
  return null;
}

/** Province attached to a numbering PREFIX, not a guaranteed caller location. */
export function provinceForPhoneNumber(raw){
  const national=geographicNationalNumber(raw);
  if(!national)return null;
  const prefix=national.slice(0,3);
  const province=prefixToProvince.get(prefix);
  if(!province)return null;
  if(prefix[0]==='8'){
    const allowed=allowedFourth[prefix];
    if(!allowed||(allowed!=='all'&&!allowed.includes(national[3])))return null;
  }
  return province;
}

/** For coverage testing and documentation only: never export caller records. */
export function provincePrefixCatalog(){
  return provinces.map(([province,prefixes])=>({
    province,prefixes:prefixes.split(' ')
  }));
}
