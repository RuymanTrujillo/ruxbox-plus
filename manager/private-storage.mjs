import fs from 'node:fs/promises';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

const runFile=promisify(execFile);
const aclPass='PRIVATE_DATA_ACL_PASS';
const winAclScript=[
  '$ErrorActionPreference="Stop"',
  '$p=$env:REAROUTER_PRIVATE_DATA_DIR',
  'if([string]::IsNullOrWhiteSpace($p)){throw "DATA_PATH_EMPTY"}',
  '$me=[Security.Principal.WindowsIdentity]::GetCurrent().User',
  '$sys=[Security.Principal.SecurityIdentifier]::new("S-1-5-18")',
  '$admins=[Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")',
  '$allowed=@($me.Value,$sys.Value,$admins.Value)',
  '$grant=[Security.AccessControl.AccessControlType]::Allow',
  '$full=[Security.AccessControl.FileSystemRights]::FullControl',
  '$flags=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit',
  '$none=[Security.AccessControl.PropagationFlags]::None',
  '$acl=Get-Acl -LiteralPath $p',
  'if($env:REAROUTER_PRIVATE_DATA_NEW -eq "1"){',
  '  $acl.SetAccessRuleProtection($true,$false)',
  '  foreach($rule in @($acl.Access)){[void]$acl.RemoveAccessRuleSpecific($rule)}',
  '  foreach($sid in @($me,$sys,$admins)){',
  '    $r=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$flags,$none,$grant)',
  '    [void]$acl.AddAccessRule($r)',
  '  }',
  '  Set-Acl -LiteralPath $p -AclObject $acl',
  '}',
  '$readback=Get-Acl -LiteralPath $p',
  // Even with no broad ACE, an untrusted OWNER can change a file's DACL.
  '$ownerSid=$readback.GetOwner([Security.Principal.SecurityIdentifier]).Value',
  'if($ownerSid -notin $allowed){throw "PRIVATE_DATA_ACL_UNTRUSTED_OWNER"}',
  // Validate the directory chain as well. A writable/deleteable parent can
  // replace a private data directory without reading its private DACL.
  // Volume roots are special: grant of DELETE on the volume root itself is
  // not a grant of DELETE_CHILD. Evaluate their dangerous bits separately.
  '$ancestor=Split-Path -Path $p -Parent',
  'while(-not [string]::IsNullOrWhiteSpace($ancestor)){',
  '  $item=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop',
  '  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw "PRIVATE_DATA_ANCESTOR_REPARSE"}',
  '  $aclParent=Get-Acl -LiteralPath $item.FullName -ErrorAction Stop',
  '$isRoot=($item.FullName -eq [IO.Path]::GetPathRoot($item.FullName))',
  '  $parentOwner=$aclParent.GetOwner([Security.Principal.SecurityIdentifier]).Value',
  '  if(!$isRoot -and $parentOwner -notin $allowed){throw "PRIVATE_DATA_PARENT_OWNER"}',
  '  $critical=[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor',
  '    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor',
  '    [Security.AccessControl.FileSystemRights]::TakeOwnership',
  '  if(!$isRoot){',
  '    $critical=$critical -bor [Security.AccessControl.FileSystemRights]::Delete -bor',
  '      [Security.AccessControl.FileSystemRights]::WriteData',
  '  }',
  '  foreach($ace in @($aclParent.Access)){',
  '    if($ace.AccessControlType -ne $grant -or',
  '      ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0){continue}',
  '    $who=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value',
  '    if($who -notin $allowed -and (($ace.FileSystemRights -band $critical) -ne 0)){',
  '      throw "PRIVATE_DATA_WRITABLE_ANCESTOR"',
  '    }',
  '  }',
  '  $next=Split-Path -Path $item.FullName -Parent',
  '  if([string]::IsNullOrWhiteSpace($next) -or $next -eq $ancestor){break}',
  '  $ancestor=$next',
  '}',
  '$hasSelf=$false',
  'foreach($ace in @($readback.Access)){',
  '  if($ace.AccessControlType -ne $grant){continue}',
  '  $sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value',
  '  if($sid -notin $allowed){throw "PRIVATE_DATA_ACL_OTHER_PRINCIPAL"}',
  '  if($sid -eq $me.Value -and (($ace.FileSystemRights -band $full) -eq $full)){$hasSelf=$true}',
  '}',
  'if(!$hasSelf){throw "PRIVATE_DATA_ACL_OWNER_ACCESS"}',
  // Existing receipts can carry explicit grants that override a safe parent
  // directory. Enumerate using a bounded, non-recursive-per-step traversal;
  // reject junctions/symlinks and unexpected grants without rewriting them.
  '$rootItem=Get-Item -LiteralPath $p -Force -ErrorAction Stop',
  'if(($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw "PRIVATE_DATA_REPARSE_ROOT"}',
  '$pending=[Collections.Generic.Stack[string]]::new()',
  '$pending.Push($p)',
  '$visited=0',
  'while($pending.Count -gt 0){',
  '  $parent=$pending.Pop()',
  '  foreach($entry in @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop)){',
  '    $visited++',
  '    if($visited -gt 20000){throw "PRIVATE_DATA_ACL_SCAN_LIMIT"}',
  '    if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw "PRIVATE_DATA_REPARSE_CHILD"}',
  '    $nestedAcl=Get-Acl -LiteralPath $entry.FullName -ErrorAction Stop',
  '    $nestedOwner=$nestedAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value',
  '    if($nestedOwner -notin $allowed){throw "PRIVATE_DATA_ACL_CHILD_OWNER"}',
  '    foreach($ace in @($nestedAcl.Access)){',
  '      if($ace.AccessControlType -ne $grant){continue}',
  '      $identity=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value',
  '      if($identity -notin $allowed){throw "PRIVATE_DATA_ACL_CHILD_GRANT"}',
  '    }',
  '    if($entry.PSIsContainer){$pending.Push($entry.FullName)}',
  '  }',
  '}',
  'Write-Output "PRIVATE_DATA_ACL_PASS"'
].join('\n');

function reject(){
  return Object.assign(new Error('La carpeta privada de datos carece de aislamiento verificable. No se inicia el gestor.'),{
    code:'PRIVATE_STORAGE_UNSAFE'
  });
}

// Check every existing path component, not just the final data directory.
// A junction in a parent can redirect a perfectly ordinary-looking data/
// folder to a different location. Check before creating anything and again
// after mkdir, because filesystem state may change between those operations.
async function assertNoReparseAncestors(target){
  const full=path.resolve(target),root=path.parse(full).root;
  let current=root;
  for(const segment of full.slice(root.length).split(path.sep).filter(Boolean)){
    current=path.join(current,segment);
    try{
      const info=await fs.lstat(current);
      if(info.isSymbolicLink()||!info.isDirectory())throw reject();
    }catch(error){
      if(error?.code==='ENOENT')continue;
      throw reject();
    }
  }
}

// Product Windows entrypoints call this before creating credentials, receipts,
// operation journals, or the instance lock. Existing directories are inspected
// but NEVER have their ACL rewritten silently.
export async function ensurePrivateDataDir(dataDir){
  if(typeof dataDir!=='string'||!path.isAbsolute(dataDir))throw reject();
  const target=path.resolve(dataDir);
  await assertNoReparseAncestors(target);
  let created=false;
  try{
    const stat=await fs.lstat(target);
    if(!stat.isDirectory()||stat.isSymbolicLink())throw reject();
  }catch(error){
    if(error?.code!=='ENOENT')throw reject();
    try{await fs.mkdir(target,{recursive:true,mode:0o700});created=true;}
    catch{throw reject();}
  }
  try{
    await assertNoReparseAncestors(target);
    const stat=await fs.lstat(target);
    if(!stat.isDirectory()||stat.isSymbolicLink())throw reject();
    if(process.platform==='win32'){
      const executable=path.join(process.env.SystemRoot||'C:/Windows',
        'System32','WindowsPowerShell','v1.0','powershell.exe');
      const encoded=Buffer.from(winAclScript,'utf16le').toString('base64');
      const {stdout}=await runFile(executable,['-NoProfile','-NonInteractive',
        '-EncodedCommand',encoded],{
        timeout:12000,maxBuffer:4096,windowsHide:true,
        env:{...process.env,REAROUTER_PRIVATE_DATA_DIR:target,
          REAROUTER_PRIVATE_DATA_NEW:created?'1':'0'}
      });
      if(stdout.trim()!==aclPass)throw reject();
    }else{
      if(created)await fs.chmod(target,0o700);
      const check=await fs.stat(target);
      if((check.mode&0o077)!==0)throw reject();
    }
    await fs.access(target,fs.constants.R_OK|fs.constants.W_OK);
  }catch{throw reject();}
  return {protected:true,created};
}
