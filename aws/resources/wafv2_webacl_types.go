package resources

import (
	"context"

	awsgo "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/aws/aws-sdk-go/service/wafv2/wafv2iface"
	"github.com/gruntwork-io/cloud-nuke/config"
	"github.com/gruntwork-io/gruntwork-cli/errors"
)

type WAFV2WebAcl struct {
	BaseAwsResource
	Client      wafv2iface.WAFV2API
	Region      string
	WebACLNames []string
}

func (waf *WAFV2WebAcl) Init(session *session.Session) {
	waf.Client = wafv2.New(session)
}

func (waf *WAFV2WebAcl) ResourceName() string {
	return "wafv2-webacl"
}

func (waf *WAFV2WebAcl) ResourceIdentifiers() []string {
	return waf.WebACLNames
}

func (waf *WAFV2WebAcl) GetAndSetResourceConfig(configObj config.Config) config.ResourceType {
	return configObj.WAFV2WebAcl
}

func (waf *WAFV2WebAcl) GetAndSetIdentifiers(c context.Context, configObj config.Config) ([]string, error) {
	identifiers, err := waf.getAll(c, configObj)
	if err != nil {
		return nil, err
	}

	waf.WebACLNames = awsgo.StringValueSlice(identifiers)
	return waf.WebACLNames, nil
}

// Nuke - nuke all WAF Web ACL Tables
func (waf *WAFV2WebAcl) Nuke(identifiers []string) error {
	if err := waf.nukeAll(awsgo.StringSlice(identifiers)); err != nil {
		return errors.WithStackTrace(err)
	}
	return nil
}
