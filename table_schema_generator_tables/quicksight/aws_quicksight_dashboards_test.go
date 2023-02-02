package quicksight





import (
	"testing"





	"github.com/aws/aws-sdk-go-v2/service/quicksight"


	"github.com/golang/mock/gomock"




	"github.com/selefra/selefra-provider-aws/aws_client"




	"github.com/selefra/selefra-provider-aws/aws_client/mocks"




	"github.com/selefra/selefra-provider-aws/faker"




	"github.com/selefra/selefra-provider-sdk/table_schema_generator"


)







func buildDashboardsMock(t *testing.T, ctrl *gomock.Controller) aws_client.AwsServices {




	m := mocks.NewMockQuicksightClient(ctrl)





	var ld quicksight.ListDashboardsOutput




	if err := faker.FakeObject(&ld); err != nil {




		t.Fatal(err)
	}


	ld.NextToken = nil




	m.EXPECT().ListDashboards(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(&ld, nil)







	var to quicksight.ListTagsForResourceOutput
	if err := faker.FakeObject(&to); err != nil {




		t.Fatal(err)


	}


	m.EXPECT().ListTagsForResource(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(&to, nil)





	return aws_client.AwsServices{




		Quicksight: m,


	}




}









func TestQuicksightDashboards(t *testing.T) {


	aws_client.MockTestHelper(t, table_schema_generator.GenTableSchema(&TableAwsQuicksightDashboardsGenerator{}), buildDashboardsMock, aws_client.TestOptions{})


}



