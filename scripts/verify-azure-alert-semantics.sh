#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
config="${1:-$root_dir/config/external-containment.json}"
subscription_id="$(jq -er .subscription_id "$config")"
workspace_id="$(jq -er .workspace_customer_id "$config")"

query='datatable(Case:string,VmId:string,RunId:string,EventType:string,Severity:string,Destination:string,DestinationPort:int)[
"explicit_violation","research","real-run","metadata_attempt","critical","169.254.169.254",80,
"boundary_probe","research","boundary-test","metadata_attempt","critical","169.254.169.254",80,
"mld_noise","gateway","real-run","firewall_egress_deny","critical","ff02:0000:0000:0000:0000:0000:0000:0016",0
]
| extend Fires = RunId != "boundary-test" and not(EventType == "firewall_egress_deny" and Destination == "ff02:0000:0000:0000:0000:0000:0000:0016" and DestinationPort == 0)
| project Case,Fires
| union (print Case="one_failure",FailureCount=1,LastFailure=now(),LastSuccess=datetime(null)),
        (print Case="three_unrecovered",FailureCount=3,LastFailure=now(),LastSuccess=datetime(null)),
        (print Case="three_recovered",FailureCount=3,LastFailure=ago(2m),LastSuccess=now())
| extend Fires=coalesce(Fires, FailureCount >= 3 and (isnull(LastSuccess) or LastSuccess < LastFailure))
| project Case,Fires'
result="$(az monitor log-analytics query --subscription "$subscription_id" --workspace "$workspace_id" --analytics-query "$query" -o json)"
jq -e '
  any(.[]; .Case=="explicit_violation" and .Fires=="True")
  and any(.[]; .Case=="boundary_probe" and .Fires=="False")
  and any(.[]; .Case=="mld_noise" and .Fires=="False")
  and any(.[]; .Case=="one_failure" and .Fires=="False")
  and any(.[]; .Case=="three_unrecovered" and .Fires=="True")
  and any(.[]; .Case=="three_recovered" and .Fires=="False")
' <<<"$result" >/dev/null
echo "AZURE ALERT SEMANTICS VERIFICATION PASSED"
