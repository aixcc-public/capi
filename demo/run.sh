#! /bin/bash

CURL="curl --location --silent --user 00000000-0000-0000-0000-000000000000:secret"

echo "Health check:"
set -x
$CURL localhost:8082/health/ | jq
set +x
echo ""

echo "Submitting VDS"
set -x
$CURL -X POST -H "Content-Type: application/json" localhost:8082/submission/vds/ -d '{"cp_name": "mock-cp", "pou": {"commit_sha1": "451dfb089f10ae0b5afd091a428e8c501c8b9b45", "sanitizer": "id_1"}, "pov": {"harness": "id_1", "data": "YWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmYWJjZGVmCmIKCjEK"}}' >vds
set +x
jq <vds
echo ""

VDS_UUID=$(jq <vds -r '.vd_uuid')
STATUS=$(jq <vds -r '.status')

while [ "$STATUS" == "pending" ]; do
	sleep 10
	echo "VDS status:"
	set -x
	$CURL "localhost:8082/submission/vds/${VDS_UUID}" >vds
	set +x
	jq <vds
	echo ""
	STATUS=$(jq <vds -r '.status')
done

echo "Final VDS Status: ${STATUS}"
if [ "$STATUS" == "rejected" ]; then
	exit 1
fi

CPV_UUID=$(jq <vds -r '.cpv_uuid')
echo ""
echo "Submitting GP"
set -x
$CURL -X POST -H "Content-Type: application/json" localhost:8082/submission/gp/ -d "{\"cpv_uuid\": \"${CPV_UUID}\", \"data\": \"ZGlmZiAtLWdpdCBhL21vY2tfdnAuYyBiL21vY2tfdnAuYwppbmRleCA1NmNmOGZkLi5hYmI3M2NkIDEwMDY0NAotLS0gYS9tb2NrX3ZwLmMKKysrIGIvbW9ja192cC5jCkBAIC0xMSw3ICsxMSw4IEBAIGludCBtYWluKCkKICAgICAgICAgcHJpbnRmKCJpbnB1dCBpdGVtOiIpOwogICAgICAgICBidWZmID0gJml0ZW1zW2ldWzBdOwogICAgICAgICBpKys7Ci0gICAgICAgIGZnZXRzKGJ1ZmYsIDQwLCBzdGRpbik7CisgICAgICAgIGZnZXRzKGJ1ZmYsIDksIHN0ZGluKTsKKyAgICAgICAgaWYgKGk9PTMpe2J1ZmZbMF09IDA7fQogICAgICAgICBidWZmW3N0cmNzcG4oYnVmZiwgIlxuIildID0gMDsKICAgICB9d2hpbGUoc3RybGVuKGJ1ZmYpIT0wKTsKICAgICBpLS07Cg==\"}" >gp
set +x
jq <gp
echo ""

GP_UUID=$(jq <gp -r '.gp_uuid')
STATUS=$(jq <gp -r '.status')

while [ "$STATUS" == "pending" ]; do
	sleep 10
	echo "GP status:"
	set -x
	$CURL "localhost:8082/submission/gp/${GP_UUID}" >gp
	set +x
	jq <gp
	echo ""
	STATUS=$(jq <gp -r '.status')
done

echo "Final GP Status: ${STATUS}"
echo ""
echo "Results"

docker exec capi-postgres-1 psql -U capi -c "select vd.commit_sha_checked_out, vd.sanitizer_fired, gp.patch_applied, gp.sanitizer_did_not_fire, gp.functional_tests_passed, vd.status as vd_status, gp.status as gp_status from vulnerability_discovery vd join generated_patch gp on vd.cpv_uuid = gp.cpv_uuid where gp.id = '${GP_UUID}'"
