package keploycli

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
    "time"
	"os"
    "path/filepath"
    "github.com/ghodss/yaml"
    
	pb "go.keploy.io/server/grpc/regression"
    "io/ioutil"
	"google.golang.org/grpc"
)

func GenerateTests() {
	// Set up a connection to the gRPC server.
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	// Create a gRPC client.
	client := pb.NewTestGenerationServiceClient(conn)
	mydir, err := os.Getwd()
	if err != nil {
        fmt.Println(err)
    }
    schemaURI:= mydir + "/keploycli/schema.json"
	fmt.Println(schemaURI)
    extension := filepath.Ext(schemaURI)

    var schemaContent string

    if extension == ".json" {
		// Read the JSON file and output the contents as a string
		schemaContents, err := ioutil.ReadFile(schemaURI)
		if err != nil {
			panic(err)
		}
		schemaContent = string(schemaContents)
	} else if extension == ".yaml" || extension == ".yml" {
		// Read the YAML file and output the contents as a string
		schemaContents, err := ioutil.ReadFile(schemaURI)
		if err != nil {
			panic(err)
		}
		output, err := yaml.YAMLToJSON(schemaContents)
		if err != nil {
			panic(err)
		}
		schemaContent = string(output)
	} else {
		// If the file is neither JSON nor YAML, throw an error
		panic("File must be a JSON or YAML file")
	}

	// Send a request to the server.
	req := &pb.KeployToServer{
		Event: pb.Event_TestGenerationTrigger,
		GenerateTestsReq: &pb.GenerateTestsReq{
			SchemaContent: schemaContent,
			BaseURL:   "http://localhost:8080/api",
		},
	}

	stream, err := client.GenerateTests(context.Background())
	if err != nil {
		log.Fatalf("Failed to call GenerateTest: %v", err)
	}

	// Send the request to the server.
	if err := stream.Send(req); err != nil {
		log.Fatalf("Failed to send request to server: %v", err)
	}

	// Receive and print the response from the server.
	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Fatalf("Failed to receive response from server: %v", err)
		}
		if resp.Event == pb.Event_ScenarioTestResponse {

            ctx := context.Background()

			request, err := http.NewRequestWithContext(ctx, resp.ScenarioTestReq.Method, resp.ScenarioTestReq.Url, bytes.NewBufferString(resp.ScenarioTestReq.Json))
            if err != nil {
                fmt.Println(err)
            }

	        reqHeaders := http.Header{}

	        for k, v := range resp.ScenarioTestReq.Headers {
		        reqHeaders.Set(k, v)
	        }
            request.Header = reqHeaders

            client := &http.Client{}

            httpresp, err := client.Do(request)

            if err != nil {
                fmt.Println(err)
            }

            headerMap := make(map[string]string)
            for key, values := range httpresp.Header {
                headerMap[key] = values[0]
            }

            date, err := time.Parse(time.RFC1123, headerMap["Date"])
            if err != nil {
                panic(err)
            }

            duration := time.Since(date).Microseconds()

            body, err := ioutil.ReadAll(httpresp.Body)
	        if err != nil {
		        fmt.Println(err)
	        }

			req := &pb.KeployToServer{
				Event: pb.Event_ScenarioTestResponse,
                ScenarioTestResp: &pb.ScenarioTestResp{
                    StatusCode: int32(httpresp.StatusCode),
                    Headers: headerMap,
                    Content: body,
                    Elapsed: duration,
                },
			}
			stream.Send(req)
		}
		if resp.Event == pb.Event_TestGenerationTrigger {
			fmt.Printf(resp.GenerateTestsResp.Output)
			break
		}
	}
}
