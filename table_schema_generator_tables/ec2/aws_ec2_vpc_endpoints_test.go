



package ec2









import (
	"testing"







	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"


	"github.com/golang/mock/gomock"
	"github.com/selefra/selefra-provider-aws/aws_client"


	"github.com/selefra/selefra-provider-aws/aws_client/mocks"


	"github.com/selefra/selefra-provider-aws/faker"




	"github.com/selefra/selefra-provider-sdk/table_schema_generator"
)









func buildEc2VpcEndpoints(t *testing.T, ctrl *gomock.Controller) aws_client.AwsServices {
	m := mocks.NewMockEc2Client(ctrl)


	e := types.VpcEndpoint{}
	if err := faker.FakeObject(&e); err != nil {




		t.Fatal(err)




	}


	m.EXPECT().DescribeVpcEndpoints(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(
		&ec2.DescribeVpcEndpointsOutput{
			VpcEndpoints: []types.VpcEndpoint{e},


		}, nil)


	return aws_client.AwsServices{




		Ec2: m,
	}


}



func TestEc2VpcEndpoints(t *testing.T) {


	aws_client.MockTestHelper(t, table_schema_generator.GenTableSchema(&TableAwsEc2VpcEndpointsGenerator{}), buildEc2VpcEndpoints, aws_client.TestOptions{})




}


