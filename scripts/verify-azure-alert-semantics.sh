#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
config="${1:-$root_dir/config/external-containment.json}"
subscription_id="$(jq -er .subscription_id "$config")"
workspace_id="$(jq -er .workspace_customer_id "$config")"

query='datatable(Case:string,VmId:string,RunId:string,EventType:string,Severity:string,Destination:string,DestinationPort:int,ObservedAt:datetime)[
"explicit_violation","research","real-run","metadata_attempt","critical","169.254.169.254",80,now(),
"boundary_probe","research","boundary-test","metadata_attempt","critical","169.254.169.254",80,now(),
"mld_noise","gateway","real-run","firewall_egress_deny","critical","ff02:0000:0000:0000:0000:0000:0000:0016",0,now()
]
| extend Fires = RunId != "boundary-test" and not(EventType == "firewall_egress_deny" and Destination == "ff02:0000:0000:0000:0000:0000:0000:0016" and DestinationPort == 0)
| project Case,Fires
| union (datatable(Case:string,FailureCount:long,LastFailure:datetime,LastSuccess:datetime)[
"one_failure",1,now(),datetime(null),
"three_unrecovered",3,now(),datetime(null),
"three_recovered",3,ago(2m),now()
] | extend Fires=FailureCount >= 3 and (isnull(LastSuccess) or LastSuccess < LastFailure) | project Case,Fires)'
result="$(az monitor log-analytics query --subscription "$subscription_id" --workspace "$workspace_id" --analytics-query "$query" -o json)"
jq -e '
  any(.[]; .Case=="explicit_violation" and .Fires==true)
  and any(.[]; .Case=="boundary_probe" and .Fires==false)
  and any(.[]; .Case=="mld_noise" and .Fires==false)
  and any(.[]; .Case=="one_failure" and .Fires==false)
  and any(.[]; .Case=="three_unrecovered" and .Fires==true)
  and any(.[]; .Case=="three_recovered" and .Fires==false)
' <<<"$result" >/dev/null
echo "AZURE ALERT SEMANTICS VERIFICATION PASSED"
