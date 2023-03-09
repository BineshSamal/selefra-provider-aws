package aws_client

import (
	"context"
	"errors"
	"fmt"
	"github.com/selefra/selefra-provider-aws/constants"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	smithy "github.com/aws/smithy-go"
	"github.com/selefra/selefra-utils/pkg/if_expression"
)

var (
	defaultRegion         = constants.Useast
	cloudfrontScopeRegion = defaultRegion
)

var envVarsToCheck = []string{
	constants.AWSPROFILE,
	constants.AWSACCESSKEYID,
	constants.AWSSECRETACCESSKEY,
	constants.AWSCONFIGFILE,
	constants.AWSROLEARN,
	constants.AWSSESSIONTOKEN,
	constants.AWSSHAREDCREDENTIALSFILE,
}

func checkEnvVariables() string {
	var result []string
	for _, v := range envVarsToCheck {
		if _, present := os.LookupEnv(v); present {
			result = append(result, v)
		}
	}
	return strings.Join(result, constants.Constants_0)
}

type Option func(client *Client)

type AwsOrg struct {
	OrganizationUnits           []string    `yaml:"organization_units,omitempty"  mapstructure:"organization_units"`
	AdminAccount                *AwsAccount `yaml:"admin_account"  mapstructure:"admin_account"`
	MemberCredentials           *AwsAccount `yaml:"member_trusted_principal"  mapstructure:"member_trusted_principal"`
	ChildAccountRoleName        string      `yaml:"member_role_name,omitempty"  mapstructure:"member_role_name"`
	ChildAccountRoleSessionName string      `yaml:"member_role_session_name,omitempty"  mapstructure:"member_role_session_name"`
	ChildAccountExternalID      string      `yaml:"member_external_id,omitempty"  mapstructure:"member_external_id"`
	ChildAccountRegions         []string    `yaml:"member_regions,omitempty"  mapstructure:"member_regions"`
}

type AwsAccount struct {
	AccountName            string   `yaml:"account_name,omitempty"  mapstructure:"account_name"`
	SharedConfigProfile    string   `yaml:"shared_config_profile,omitempty"  mapstructure:"shared_config_profile"`
	SharedConfigFiles      []string `yaml:"shared_config_files"  mapstructure:"shared_config_files"`
	SharedCredentialsFiles []string `yaml:"shared_credentials_files"  mapstructure:"shared_credentials_files"`
	RoleARN                string   `yaml:"role_arn,omitempty"  mapstructure:"role_arn"`
	RoleSessionName        string   `yaml:"role_session_name,omitempty"  mapstructure:"role_session_name"`
	ExternalID             string   `yaml:"external_id,omitempty"  mapstructure:"external_id"`
	DefaultRegion          string   `yaml:"default_region,omitempty"  mapstructure:"default_region"`
	Regions                []string `yaml:"regions,omitempty"  mapstructure:"regions"`
	source                 string
}

var (
	DefaultMaxAttempts = 10
	DefaultMaxBackoff  = 30
)

type AwsProviderConfig struct {
	Accounts     []AwsAccount `yaml:"accounts"  mapstructure:"accounts"`
	MaxAttempts  int          `yaml:"max_attempts,omitempty"  mapstructure:"max_attempts"`
	MaxBackoff   int          `yaml:"max_backoff,omitempty" mapstructure:"max_backoff"`
	Organization *AwsOrg      `yaml:"org" mapstructure:"org"`
	Regions      []string
}

func verifyRegions(regions []string) error {
	if serviceRegionDataTransport == nil {
		return errors.New(constants.ServiceRegiondatanotinitialized)
	}

	var hasWildcard bool
	for i, region := range regions {
		if region == constants.Constants_1 {
			hasWildcard = true
		}
		if (i != 0 && region == constants.Constants_2) || (i > 0 && hasWildcard) {
			return errors.New(constants.Regionwildcardisonlysupportedasfirstargument)
		}

		_, regionExist := serviceRegionDataTransport.regionSet[region]
		if !hasWildcard && !regionExist {
			return fmt.Errorf(constants.Regionsisnotsupported, region)
		}
	}
	return nil
}

func filterDisabledRegions(regions []string, enabledRegions []ec2types.Region) []string {
	regionsMap := map[string]bool{}
	for _, r := range enabledRegions {
		if r.RegionName != nil && r.OptInStatus != nil && *r.OptInStatus != constants.Notoptedin {
			regionsMap[*r.RegionName] = true
		}
	}

	var filteredRegions []string

	if isAllRegions(regions) {
		for region := range regionsMap {
			filteredRegions = append(filteredRegions, region)
		}
	} else {
		for _, r := range regions {
			if regionsMap[r] {
				filteredRegions = append(filteredRegions, r)
			}
		}
	}
	return filteredRegions
}

func isAllRegions(regions []string) bool {
	err := verifyRegions(regions)
	if err != nil {
		return false
	}

	wildcardAllRegions := false
	if (len(regions) == 1 && regions[0] == constants.Constants_3) || (len(regions) == 0) {
		wildcardAllRegions = true
	}
	return wildcardAllRegions
}

func newAwsConfig(ctx context.Context, cfg *AwsProviderConfig, account AwsAccount, stsClient *sts.Client) (aws.Config, error) {
	var err error
	var awsCfg aws.Config
	configFns := []func(*config.LoadOptions) error{
		config.WithDefaultRegion(defaultRegion),
		config.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = cfg.MaxAttempts
				o.MaxBackoff = time.Second * time.Duration(cfg.MaxBackoff)
			})
		}),
	}

	if account.SharedConfigProfile != constants.Constants_4 {
		configFns = append(configFns, config.WithSharedConfigProfile(account.SharedConfigProfile))
	}

	if len(account.SharedConfigFiles) != 0 {
		configFns = append(configFns, config.WithSharedConfigFiles(account.SharedConfigFiles))
	}

	if len(account.SharedCredentialsFiles) != 0 {
		configFns = append(configFns, config.WithSharedCredentialsFiles(account.SharedCredentialsFiles))
	}

	if account.DefaultRegion != constants.Constants_5 {
		configFns = append(configFns, config.WithDefaultRegion(account.DefaultRegion))
	}

	awsCfg, err = config.LoadDefaultConfig(ctx, configFns...)

	if err != nil {
		return awsCfg, err
	}

	if account.RoleARN != constants.Constants_6 {
		opts := make([]func(*stscreds.AssumeRoleOptions), 0, 1)
		if account.ExternalID != constants.Constants_7 {
			opts = append(opts, func(opts *stscreds.AssumeRoleOptions) {
				opts.ExternalID = &account.ExternalID
			})
		}
		if account.RoleSessionName != constants.Constants_8 {
			opts = append(opts, func(opts *stscreds.AssumeRoleOptions) {
				opts.RoleSessionName = account.RoleSessionName
			})
		}
		if stsClient == nil {
			stsClient = sts.NewFromConfig(awsCfg)
		}
		provider := stscreds.NewAssumeRoleProvider(stsClient, account.RoleARN, opts...)

		awsCfg.Credentials = aws.NewCredentialsCache(provider)
	}

	if _, err := awsCfg.Credentials.Retrieve(ctx); err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if strings.Contains(ae.ErrorCode(), constants.InvalidClientTokenId) {
				return awsCfg, errors.New(constants.ThecredentialsbeingusedtoassumeroleareinvalidPleasecheckthatyourcredentialsarevalidinthePartitionyouareusingIfyouareusingaPartitionotherthantheAWScommercialRegionbesuresetthedefaultregionattributeintheconfigfile)
			}
		}
		return awsCfg, errors.New(constants.Couldntfindanycredentialsinenvironmentvariablesorconfigurationfiles)
	}
	return awsCfg, nil
}

type Client struct {
	config aws.Config

	Partition string
	AccountID string
	Region    string

	AutoscalingNamespace string
	WAFScope             types.Scope

	accountAwsServiceManager *AwsServicesManager
}

func NewClients(config AwsProviderConfig) ([]*Client, error) {

	return newClient(config)
}

func newClient(config AwsProviderConfig) ([]*Client, error) {
	ctx := context.Background()
	var stsClient *sts.Client
	var clients []*Client
	var accounts []AwsAccount

	config.MaxAttempts = if_expression.ReturnInt(config.MaxAttempts == 0, DefaultMaxAttempts, config.MaxAttempts)
	config.MaxBackoff = if_expression.ReturnInt(config.MaxBackoff == 0, DefaultMaxBackoff, config.MaxBackoff)

	if config.Organization != nil {
		var err error
		accounts, stsClient, err = loadOrgAccounts(ctx, &config)
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if strings.Contains(ae.ErrorCode(), constants.AccessDenied) {
					return nil, errors.New(constants.FailedtolistOrgmemberaccountsMakesurethatyourcredentialshavetheproperpermissions)
				}
			}
			return nil, err
		}
	}

	for _, account := range config.Accounts {
		account.source = constants.AccountID
		accounts = append(accounts, account)
	}

	if len(accounts) == 0 {
		accounts = append(accounts, AwsAccount{
			AccountName: constants.Default,
			source:      constants.Default,
		})
	}
	for _, account := range accounts {
		localRegions := account.Regions
		if len(localRegions) == 0 {
			localRegions = config.Regions
		}

		if err := verifyRegions(localRegions); err != nil {
			return nil, err
		}

		awsCfg, err := newAwsConfig(ctx, &config, account, stsClient)
		if err != nil {
			if account.source == constants.Org {
				principal := constants.Unknownprincipal

				awsAdminCfg, _ := newAwsConfig(ctx, &config, *config.Organization.AdminAccount, nil)
				output, accountErr := sts.NewFromConfig(awsAdminCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
				if accountErr == nil {
					principal = *output.Arn
				}

				fmt.Printf(constants.EnsurethatshasaccesstobeableperformstsAssumeRoleonsn, principal, account.RoleARN)

				continue
			}
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if strings.Contains(ae.ErrorCode(), constants.AccessDenied) {
					fmt.Printf(constants.FailedtoretrievecredentialsforAccountIDsAWSErrorsdetectedawsenvvariablessn, account.AccountName, err.Error(), checkEnvVariables())
					continue
				}
			}

			return nil, err
		}

		res, err := ec2.NewFromConfig(awsCfg).DescribeRegions(ctx,
			&ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)},
			func(o *ec2.Options) {
				o.Region = defaultRegion
				if account.DefaultRegion != constants.Constants_9 {
					o.Region = account.DefaultRegion
				}

				if len(localRegions) > 0 && !isAllRegions(localRegions) {
					o.Region = localRegions[0]
				}
			})

		if err != nil {
			errorMsg := strings.Builder{}
			errorMsg.WriteString(fmt.Sprintf("Failed to find regions for AccountID %s. ", account.AccountName))
			if strings.Contains(err.Error(), "AuthFailure") {
				errorMsg.WriteString("The authentication you configured does not have EC2 read permission. ")
			}
			errorMsg.WriteString(fmt.Sprintf("AWS Error: %s", err.Error()))
			fmt.Printf(errorMsg.String())
			continue
		}

		account.Regions = filterDisabledRegions(localRegions, res.Regions)

		if len(account.Regions) == 0 {
			fmt.Printf(constants.NoenabledregionsprovidedinconfigforAccountIDs, account.AccountName)
			continue
		}
		awsCfg.Region = account.Regions[0]
		output, err := sts.NewFromConfig(awsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {

			fmt.Printf(constants.FailedtogetcalleridentityAWSErrors, err.Error())
			continue
		}
		iamArn, err := arn.Parse(*output.Arn)
		if err != nil {
			return nil, err
		}

		client := NewAwsClient(awsCfg, SetAccount(*output.Account), SetPartition(iamArn.Partition))

		accountAwsServiceManager := NewAwsServiceCache(&awsCfg)
		client.accountAwsServiceManager = accountAwsServiceManager
		var register bool

		for _, region := range account.Regions {
			if region == defaultRegion {
				register = true
			}
			accountAwsServiceManager.initAwsServices(client.Partition, region)
		}
		if !register {
			accountAwsServiceManager.initAwsServices(client.Partition, defaultRegion)
		}

		accountAwsServiceManager.initAwsServices(client.Partition, cloudfrontScopeRegion)

		if client.accountAwsServiceManager.CacheCount() == 0 {
			return nil, errors.New(constants.Noaccountsinstantiated)
		}
		clients = append(clients, client)
	}

	if len(clients) == 0 {
		return nil, errors.New(constants.Noaccountsinstantiated)
	}

	return clients, nil

}

func (c *Client) Copy(opts ...Option) *Client {
	cc := &Client{
		config:                   c.config,
		AccountID:                c.AccountID,
		Region:                   c.Region,
		AutoscalingNamespace:     c.AutoscalingNamespace,
		WAFScope:                 c.WAFScope,
		Partition:                c.Partition,
		accountAwsServiceManager: c.accountAwsServiceManager,
	}
	for _, opt := range opts {
		opt(cc)
	}
	return cc
}

func (c *Client) GetAccount() string {
	return c.AccountID
}

func (c *Client) GetRegion() string {
	return c.Region
}

func (c *Client) GetWAFScope() types.Scope {
	return c.WAFScope
}

func (c *Client) GetPartition() string {
	return c.Partition
}

func (c *Client) GetAutoscalingNamespace() string {
	return c.AutoscalingNamespace
}

func SetRegion(region string) Option {
	return func(c *Client) {
		if region == constants.Constants_10 {
			return
		}
		c.Region = region
	}
}

func SetPartition(partition string) Option {
	return func(c *Client) {
		if partition == constants.Constants_11 {
			return
		}
		c.Partition = partition
	}
}

func SetAccount(account string) Option {
	return func(c *Client) {
		if account == constants.Constants_12 {
			return
		}
		c.AccountID = account
	}
}

func SetAutoscalingNamespace(autoscalingNamespace string) Option {
	return func(client *Client) {
		client.AutoscalingNamespace = autoscalingNamespace
	}
}

func SetWAFScope(cp types.Scope) Option {
	return func(client *Client) {
		client.WAFScope = cp
	}
}

func (c *Client) IsNotFoundError(err error) bool {
	if isNotFoundError(err) {
		return true
	}
	return false
}

func (c *Client) IsAccessDeniedError(err error) bool {
	if isAccessDeniedError(err) {
		return true
	}
	return false
}

func (c *Client) AwsServices() *AwsServices {

	awsServices := c.accountAwsServiceManager.Get(c.Partition, c.Region)
	if awsServices == nil && c.WAFScope == types.ScopeCloudfront {

		return c.accountAwsServiceManager.Get(c.Partition, constants.Constants_13)
	}
	return awsServices
}

func (c *Client) ARN(service string, idParts ...string) string {
	return makeARN(service, c.Partition, c.AccountID, c.GetRegion(), idParts...).String()
}

func NewAwsClient(cfg aws.Config, ops ...Option) *Client {
	cli := &Client{
		config:               cfg,
		Region:               defaultRegion,
		AutoscalingNamespace: constants.Constants_14,
		WAFScope:             "",
		Partition:            constants.Constants_16,
	}
	for _, op := range ops {
		op(cli)
	}
	return cli
}

func (c *Client) AccountGlobalARN(service string, idParts ...string) string {
	return makeARN(service, c.Partition, c.AccountID, constants.Constants_17, idParts...).String()
}
