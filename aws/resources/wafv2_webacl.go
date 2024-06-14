package resources

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/gruntwork-io/cloud-nuke/config"
	"github.com/gruntwork-io/cloud-nuke/logging"
	"github.com/gruntwork-io/cloud-nuke/report"
	"github.com/gruntwork-io/go-commons/errors"
)

func (waf *WAFV2WebAcl) getAll(c context.Context, configObj config.Config) ([]*string, error) {
	var webAcls []*string
	l := wafv2.ListWebACLsInput{}
	l.SetScope("REGIONAL")
	aclsDetail, err := waf.Client.ListWebACLs(&l)
	if err != nil {
		log.Fatalf("There was an error describing Waf ACLs: %v\n", err)
		return nil, err
	}

	for _, item := range aclsDetail.WebACLs {
		webAcls = append(webAcls, item.Id)
	}

	return webAcls, nil
}

func stringExists(s *string, slice []*string) bool {
    for _, item := range slice {
        if *item == *s {
            return true
        }
    }
    return false
}

func (waf *WAFV2WebAcl) nukeAll(acls []*string) error {
	if len(acls) == 0 {
		logging.Debugf("No WAF Web ACLs to nuke in region %s", waf.Region)
		return nil
	}

	logging.Debugf("Deleting all WAF Web ACLs in region %s", waf.Region)

	l := wafv2.ListWebACLsInput{}
	l.SetScope("REGIONAL")
	aclsDetail, errList := waf.Client.ListWebACLs(&l)
	if errList != nil {
		log.Fatalf("There was an error describing Waf ACLs: %v\n", errList)
		return errList
	}

	for _, item := range aclsDetail.WebACLs {
		logging.Debugf("Debug: AWS ACL ID: %s\n", *item.Id)		
		
		if stringExists(item.Id, acls) {
			logging.Debugf("Debug: Deleteing AWS ACL ID: %s\n", *item.Id)
			input := &wafv2.DeleteWebACLInput{}
			input.SetId(*item.Id)
			logging.Debugf("id: %s", *item.Id)
			input.SetScope("REGIONAL")
			input.SetLockToken(*item.LockToken)
			logging.Debugf("LockToken: %s", *item.LockToken)
			input.SetName(*item.Name)
			logging.Debugf("Name: %s", *item.Name)

			detachResourcesFromACL(waf, item)

			_, err := waf.Client.DeleteWebACLWithContext(waf.Context, input)
			if err != nil {
				logging.Debugf("There was an error deleteing Waf ACLs: %v\n", err)				
			}

			// Record status of this resource
			e := report.Entry{
				Identifier:   aws.StringValue(item.Id),
				ResourceType: "WEBACL",
				Error:        err,
			}
			report.Record(e)

			if err != nil {
				if aerr, ok := err.(awserr.Error); ok {
					switch aerr.Error() {
					case wafv2.ErrCodeWAFInternalErrorException:
						return errors.WithStackTrace(aerr)
					default:
						return errors.WithStackTrace(aerr)
					}
				}
			}
		}
	}

	return nil
}

// Detach all associated resources to allow deleting the WebACL
func detachResourcesFromACL(waf *WAFV2WebAcl, item *wafv2.WebACLSummary){
	
	var asso =[]string {"APPLICATION_LOAD_BALANCER","API_GATEWAY","APPSYNC","COGNITO_USER_POOL","APP_RUNNER_SERVICE","VERIFIED_ACCESS_INSTANCE"}

	res := &wafv2.ListResourcesForWebACLInput{}
	res.SetWebACLArn(*item.ARN)
	for _, v := range asso {
		res.SetResourceType(v)
		listResourcesForWebACLOutput, err := waf.Client.ListResourcesForWebACL(res)
		if err != nil {
			logging.Debugf("There was an error Getting Waf ACLs Attachemnts: %v\n", err)				
		}
		for _, alb := range listResourcesForWebACLOutput.ResourceArns {
			_, err := waf.Client.DisassociateWebACL(&wafv2.DisassociateWebACLInput{
				ResourceArn: alb,
			})
			if err != nil {
				logging.Debugf("There was an error DisassociateWebACL Waf ACLs: %v\n", err)				
			}
		}
	}
}