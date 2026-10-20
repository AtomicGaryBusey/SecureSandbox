#!/usr/bin/env python3
"""Upload opaque transcript ciphertext to Azure Blob with add-only credentials."""

from azure_shipper import get_token, request_pinned
import hashlib, json, os, re, time, urllib.parse

SPOOL="/var/lib/secure-sandbox/conversation-spool"
SECRET="/run/credentials/conversation-azure-shipper.service/client_secret"
NAME_RE=re.compile(r"^(?:[0-9a-f-]{36}|(?:artifact|source)-[0-9a-f-]{36})-[0-9]{12}-[0-9a-f]{64}\.age$")

def upload(config, token, name, body):
    path=f"/{config['container']}/{urllib.parse.quote(name,safe='-')}"
    status,payload=request_pinned(config["storage_host"],config["storage_ipv4"],"PUT",path,body,{
      "Authorization":f"Bearer {token}","x-ms-version":"2023-11-03","x-ms-blob-type":"BlockBlob",
      "Content-Type":"application/age","Content-Length":str(len(body)),"If-None-Match":"*",
      "x-ms-meta-sha256":hashlib.sha256(body).hexdigest()})
    if status not in (201,412):
        match=re.search(br"<Code>([A-Za-z0-9]+)</Code>",payload)
        code=match.group(1).decode("ascii") if match else "Unknown"
        # The create-only role intentionally cannot authorize an overwrite,
        # so Azure returns this instead of evaluating If-None-Match. Names are
        # content-addressed with SHA-256; an existing identical name is the
        # idempotent-success case after a lost response.
        if status == 403 and code == "UnauthorizedBlobOverwrite":
            return
        raise RuntimeError(f"blob status {status} code {code}")

def main():
    with open("/etc/secure-sandbox/conversation-azure.json",encoding="utf-8") as h: config=json.load(h)
    config["token_scope"]="https://storage.azure.com/.default"
    with open(SECRET,encoding="utf-8") as h: secret=h.read().strip()
    token=""; expiry=0.0
    while True:
      try:
        names=sorted(n for n in os.listdir(SPOOL) if NAME_RE.fullmatch(n))
        if not names: time.sleep(2); continue
        name=names[0]; path=os.path.join(SPOOL,name)
        with open(path,"rb") as h: body=h.read()
        if hashlib.sha256(body).hexdigest()!=name[-68:-4]: raise RuntimeError("ciphertext hash mismatch")
        if time.monotonic()>=expiry:
          token,expiry=get_token(config,secret)
        upload(config,token,name,body); os.unlink(path)
        if name.startswith("artifact-"):
          event="artifact_blob_uploaded"
        elif name.startswith("source-"):
          event="source_manifest_blob_uploaded"
        else:
          event="conversation_blob_uploaded"
        print(json.dumps({"event":event,"name":name,"bytes":len(body)}),flush=True)
      except Exception as error:
        name=locals().get("name","")
        if name.startswith("artifact-"):
          event="artifact_blob_upload_failed"
        elif name.startswith("source-"):
          event="source_manifest_blob_upload_failed"
        else:
          event="conversation_blob_upload_failed"
        print(json.dumps({"event":event,"name":name,"error":type(error).__name__,"detail":str(error)[:160]}),flush=True); time.sleep(10)

if __name__=="__main__": main()
