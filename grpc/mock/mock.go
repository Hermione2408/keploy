package mock

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"unicode/utf8"

	proto "go.keploy.io/server/grpc/regression"
	"go.keploy.io/server/grpc/utils"
	"go.keploy.io/server/pkg"
	"go.keploy.io/server/pkg/models"
	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"
)

func EncodeMongoMessage(spec *models.MongoSpec, doc *proto.Mock) error {
	
	// encode mongoRequest into yaml
	switch spec.RequestHeader.Opcode {
	case wiremessage.OpReply:
		err := spec.Request.Encode(models.MongoOpReply{
			ResponseFlags: doc.Spec.MongoRequest.ResponseFlags,
			CursorID: doc.Spec.MongoRequest.CursorID,
			StartingFrom: doc.Spec.MongoRequest.StartingFrom,
			NumberReturned: doc.Spec.MongoRequest.NumberReturned,
			Documents: doc.Spec.MongoRequest.Documents,
		}) 
		if err!=nil {
			return fmt.Errorf("failed to encode mongo request of type OpReply for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	case wiremessage.OpQuery:
		err := spec.Request.Encode(models.MongoOpQuery{
			Flags: doc.Spec.MongoRequest.Flags,
			FullCollectionName: doc.Spec.MongoRequest.FullCollectionName,
			NumberToSkip: doc.Spec.MongoRequest.NumberToSkip,
			NumberToReturn: doc.Spec.MongoRequest.NumberToReturn,
			Query: doc.Spec.MongoRequest.Query,
			ReturnFieldsSelector: doc.Spec.MongoRequest.ReturnFieldsSelector,
		})	
		if err!=nil {
			return fmt.Errorf("failed to encode mongo request of type OpQuery for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	case wiremessage.OpMsg:
		err := spec.Request.Encode(models.MongoOpMessage{
			FlagBits: int(doc.Spec.MongoRequest.FlagBits),
			Sections: doc.Spec.MongoRequest.Sections,
			Checksum: int(doc.Spec.MongoRequest.Checksum),
		})
		if err!=nil {
			return fmt.Errorf("failed to encode mongo request of type OpMsg for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	}

	// encode mongoResponse into yaml
	switch spec.ResponseHeader.Opcode {
	case wiremessage.OpReply:
		err := spec.Response.Encode(models.MongoOpReply{
			ResponseFlags: doc.Spec.MongoResponse.ResponseFlags,
			CursorID: doc.Spec.MongoResponse.CursorID,
			StartingFrom: doc.Spec.MongoResponse.StartingFrom,
			NumberReturned: doc.Spec.MongoResponse.NumberReturned,
			Documents: doc.Spec.MongoResponse.Documents,
		}) 
		if err!=nil {
			return fmt.Errorf("failed to encode mongo response of type OpReply for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	case wiremessage.OpQuery:
		err := spec.Response.Encode(models.MongoOpQuery{
			Flags: doc.Spec.MongoResponse.Flags,
			FullCollectionName: doc.Spec.MongoResponse.FullCollectionName,
			NumberToSkip: doc.Spec.MongoResponse.NumberToSkip,
			NumberToReturn: doc.Spec.MongoResponse.NumberToReturn,
			Query: doc.Spec.MongoResponse.Query,
			ReturnFieldsSelector: doc.Spec.MongoResponse.ReturnFieldsSelector,
		})	
		if err!=nil {
			return fmt.Errorf("failed to encode mongo response of type OpQuery for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	case wiremessage.OpMsg:
		err := spec.Response.Encode(models.MongoOpMessage{
			FlagBits: int(doc.Spec.MongoResponse.FlagBits),
			Sections: doc.Spec.MongoResponse.Sections,
			Checksum: int(doc.Spec.MongoResponse.Checksum),
		})
		if err!=nil {
			return fmt.Errorf("failed to encode mongo response of type OpMsg for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	}
	return nil
}

func DecodeMongoMessage (spec *models.MongoSpec, doc *proto.Mock) error {
	// mongo request
	switch doc.Spec.RequestHeader.OpCode {
	case int32(wiremessage.OpMsg):
		req := &models.MongoOpMessage{}
		err := spec.Request.Decode(req)
		if err != nil {
			return fmt.Errorf("failed to decode the mongo OpMsg of mock with name: %s.  error: %s", doc.Name, err.Error())
		}
		doc.Spec.MongoRequest = &proto.MongoMessage{
			FlagBits: int64(req.FlagBits),
			Sections: req.Sections,
			Checksum: int64(req.Checksum),
		}
	case int32(wiremessage.OpReply):
		req := &models.MongoOpReply{}
		err := spec.Request.Decode(req)
		if err != nil {
			return fmt.Errorf("failed to decode the mongo OpReply of mock with name: %s.  error: %s", doc.Name, err.Error())
		}
		doc.Spec.MongoRequest = &proto.MongoMessage{
			ResponseFlags: req.ResponseFlags,
			CursorID: req.CursorID,
			StartingFrom: req.StartingFrom,
			NumberReturned: req.NumberReturned,
			Documents: req.Documents,
		}
	case int32(wiremessage.OpQuery):
		req := &models.MongoOpQuery{}
		err := spec.Request.Decode(req)
		if err != nil {
			return fmt.Errorf("failed to decode the mongo OpReply of mock with name: %s.  error: %s", doc.Name, err.Error())
		}
		doc.Spec.MongoRequest = &proto.MongoMessage{
			Flags: req.Flags,
			FullCollectionName: req.FullCollectionName,
			NumberToSkip: req.NumberToSkip,
			NumberToReturn: req.NumberToReturn,
			Query: req.Query,
			ReturnFieldsSelector: req.ReturnFieldsSelector,
		}
	default:
		// TODO
	}

	// mongo response
	switch doc.Spec.ResponseHeader.OpCode {
	case int32(wiremessage.OpMsg):
		resp := &models.MongoOpMessage{}
		err := spec.Response.Decode(resp)
		if err != nil {
			return fmt.Errorf("failed to decode the mongo OpMsg of mock with name: %s.  error: %s", doc.Name, err.Error())
		}
		doc.Spec.MongoResponse = &proto.MongoMessage{
			FlagBits: int64(resp.FlagBits),
			Sections: resp.Sections,
			Checksum: int64(resp.Checksum),
		}
	case int32(wiremessage.OpReply):
		resp := &models.MongoOpReply{}
		err := spec.Response.Decode(resp)
		if err != nil {
			return fmt.Errorf("failed to decode the mongo OpReply of mock with name: %s.  error: %s", doc.Name, err.Error())
		}
		doc.Spec.MongoResponse = &proto.MongoMessage{
			ResponseFlags: resp.ResponseFlags,
			CursorID: resp.CursorID,
			StartingFrom: resp.StartingFrom,
			NumberReturned: resp.NumberReturned,
			Documents: resp.Documents,
		}
	case int32(wiremessage.OpQuery):
		resp := &models.MongoOpQuery{}
		err := spec.Response.Decode(resp)
		if err != nil {
			return fmt.Errorf("failed to decode the mongo OpReply of mock with name: %s.  error: %s", doc.Name, err.Error())
		}
		doc.Spec.MongoResponse = &proto.MongoMessage{
			Flags: resp.Flags,
			FullCollectionName: resp.FullCollectionName,
			NumberToSkip: resp.NumberToSkip,
			NumberToReturn: resp.NumberToReturn,
			Query: resp.Query,
			ReturnFieldsSelector: resp.ReturnFieldsSelector,
		}
	default:
		// TODO
	}
	return nil
}

func Encode(doc *proto.Mock) (models.Mock, error) {
	res := models.Mock{
		Version: models.Version(doc.Version),
		Kind:    models.Kind(doc.Kind),
		Name:    doc.Name,
	}
	switch doc.Kind {
	case string(models.Mongo):

		spec := models.MongoSpec{
			Metadata: doc.Spec.Metadata,
			RequestHeader: models.MongoHeader{
				Length: doc.Spec.RequestHeader.Length,
				RequestID: doc.Spec.RequestHeader.RequestId,
				ResponseTo: doc.Spec.RequestHeader.ResponseTo,
				Opcode: wiremessage.OpCode(doc.Spec.RequestHeader.OpCode),
			},
			ResponseHeader: models.MongoHeader{
				Length: doc.Spec.ResponseHeader.Length,
				RequestID: doc.Spec.ResponseHeader.RequestId,
				ResponseTo: doc.Spec.ResponseHeader.ResponseTo,
				Opcode: wiremessage.OpCode(doc.Spec.ResponseHeader.OpCode),
			},
			// Request: ,
			// RequestMessage: models.MongoMessage{
			// 	Header: models.MongoHeader{
			// 		Length:     doc.Spec.RequestMongoMessage.Header.Length,
			// 		RequestID:  doc.Spec.RequestMongoMessage.Header.RequestId,
			// 		ResponseTo: doc.Spec.RequestMongoMessage.Header.ResponseTo,
			// 		Opcode:     wiremessage.OpCode(doc.Spec.RequestMongoMessage.Header.OpCode),
			// 	},
			// 	FlagBits: int(doc.Spec.RequestMongoMessage.FlagBits),
			// 	Sections: doc.Spec.RequestMongoMessage.Sections,
			// 	Checksum: int(doc.Spec.RequestMongoMessage.Checksum),
			// },
			// ResponseMessage: models.MongoMessage{
			// 	Header: models.MongoHeader{
			// 		Length:     doc.Spec.ResponseMongoMessage.Header.Length,
			// 		RequestID:  doc.Spec.ResponseMongoMessage.Header.RequestId,
			// 		ResponseTo: doc.Spec.ResponseMongoMessage.Header.ResponseTo,
			// 		Opcode:     wiremessage.OpCode(doc.Spec.ResponseMongoMessage.Header.OpCode),
			// 	},
			// 	FlagBits: int(doc.Spec.ResponseMongoMessage.FlagBits),
			// 	Sections: doc.Spec.ResponseMongoMessage.Sections,
			// 	Checksum: int(doc.Spec.ResponseMongoMessage.Checksum),
			// },
		}

		err := EncodeMongoMessage(&spec, doc)
		if err != nil {
			return res, err
		}
		err = res.Spec.Encode(&spec)
		if err != nil {
			return res, fmt.Errorf("failed to encode mongo spec for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	case string(models.HTTP):
		spec := models.HttpSpec{
			Metadata: doc.Spec.Metadata,
			Request: models.MockHttpReq{
				Method:     models.Method(doc.Spec.Req.Method),
				ProtoMajor: int(doc.Spec.Req.ProtoMajor),
				ProtoMinor: int(doc.Spec.Req.ProtoMinor),
				URL:        doc.Spec.Req.URL,
				Header:     ToMockHeader(utils.GetHttpHeader(doc.Spec.Req.Header)),
				Body:       string(doc.Spec.Req.Body),
				BodyType:   string(models.BodyTypeUtf8),
				Form:       GetMockFormData(doc.Spec.Req.Form),
			},
			Response: models.MockHttpResp{
				StatusCode:    int(doc.Spec.Res.StatusCode),
				Header:        ToMockHeader(utils.GetHttpHeader(doc.Spec.Res.Header)),
				Body:          string(doc.Spec.Res.Body),
				BodyType:      string(models.BodyTypeUtf8),
				StatusMessage: doc.Spec.Res.StatusMessage,
				ProtoMajor:    int(doc.Spec.Res.ProtoMajor),
				ProtoMinor:    int(doc.Spec.Res.ProtoMinor),
				Binary:        doc.Spec.Res.Binary,
			},
			Objects:    ToModelObjects(doc.Spec.Objects),
			Mocks:      doc.Spec.Mocks,
			Assertions: utils.GetHttpHeader(doc.Spec.Assertions),
			Created:    doc.Spec.Created,
		}
		if doc.Spec.Req.BodyData != nil {
			if !utf8.ValidString(string(doc.Spec.Req.BodyData)) {
				spec.Request.BodyType = string(models.BodyTypeBinary)
				spec.Request.Body = base64.StdEncoding.EncodeToString(doc.Spec.Req.BodyData)
			} else {
				spec.Request.Body = string(doc.Spec.Req.BodyData)
			}
		}
		if doc.Spec.Res.BodyData != nil {
			if !utf8.ValidString(string(doc.Spec.Res.BodyData)) {
				spec.Response.BodyType = string(models.BodyTypeBinary)
				spec.Response.Body = base64.StdEncoding.EncodeToString(doc.Spec.Res.BodyData)
			} else {
				spec.Response.Body = string(doc.Spec.Res.BodyData)
			}
		}

		err := res.Spec.Encode(&spec)
		if err != nil {
			return res, fmt.Errorf("failed to encode http spec for mock with name: %s.  error: %s", doc.Name, err.Error())
		}

	case string(models.SQL):
		spec := models.SQlSpec{
			Type:     models.SqlOutputType(doc.Spec.Type),
			Metadata: doc.Spec.Metadata,
			Int:      int(doc.Spec.Int),
			Err:      doc.Spec.Err,
		}
		if doc.Spec.Table != nil {
			spec.Table = models.Table{
				Cols: ToModelCols(doc.Spec.Table.Cols),
				Rows: doc.Spec.Table.Rows,
			}
		}
		err := res.Spec.Encode(&spec)
		if err != nil {
			return res, fmt.Errorf("failed to encode sql spec for mock with name: %s.  error: %s", doc.Name, err.Error())
		}

	case string(models.GENERIC):
		err := res.Spec.Encode(&models.GenericSpec{
			Metadata: doc.Spec.Metadata,
			Objects:  ToModelObjects(doc.Spec.Objects),
		})
		if err != nil {
			return res, fmt.Errorf("failed to encode generic spec for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	case string(models.GRPC_EXPORT):
		spec := models.GrpcSpec{
			Metadata: doc.Spec.Metadata,
			Request: models.GrpcReq{
				Body:   doc.Spec.GrpcRequest.Body,
				Method: doc.Spec.GrpcRequest.Method,
			},
			// Request: models.MockHttpReq{
			// 	Method:     models.Method(doc.Spec.Req.Method),
			// 	ProtoMajor: int(doc.Spec.Req.ProtoMajor),
			// 	ProtoMinor: int(doc.Spec.Req.ProtoMinor),
			// 	URL:        doc.Spec.Req.URL,
			// 	Header:     ToMockHeader(utils.GetHttpHeader(doc.Spec.Req.Header)),
			// 	Body:       doc.Spec.Req.Body,
			// },
			// Response: models.MockHttpResp{
			// 	StatusCode:    int(doc.Spec.Res.StatusCode),
			// 	Header:        ToMockHeader(utils.GetHttpHeader(doc.Spec.Res.Header)),
			// 	Body:          doc.Spec.Res.Body,
			// 	StatusMessage: doc.Spec.Res.StatusMessage,
			// 	ProtoMajor:    int(doc.Spec.Res.ProtoMajor),
			// 	ProtoMinor:    int(doc.Spec.Res.ProtoMinor),
			// },
			Response: models.GrpcResp{
				Body: doc.Spec.GrpcResp.Body,
				Err:  doc.Spec.GrpcResp.Err,
			},
			Objects:    ToModelObjects(doc.Spec.Objects),
			Mocks:      doc.Spec.Mocks,
			Assertions: utils.GetHttpHeader(doc.Spec.Assertions),
			Created:    doc.Spec.Created,
		}
		for _, j := range doc.Spec.Objects {
			spec.Objects = append(spec.Objects, models.Object{Type: j.Type, Data: string(j.Data)})
		}
		err := res.Spec.Encode(&spec)
		if err != nil {
			return res, fmt.Errorf("failed to encode http spec for mock with name: %s.  error: %s", doc.Name, err.Error())
		}
	default:
		return res, fmt.Errorf("mock with name %s is not of a valid kind", doc.Name)
	}
	return res, nil
}

func ToModelCols(cols []*proto.SqlCol) []models.SqlCol {
	res := []models.SqlCol{}
	for _, j := range cols {
		res = append(res, models.SqlCol{
			Name:      j.Name,
			Type:      j.Type,
			Precision: int(j.Precision),
			Scale:     int(j.Scale),
		})
	}
	return res
}

func toProtoCols(cols []models.SqlCol) ([]*proto.SqlCol, error) {
	if len(cols) == 0 {
		return nil, nil
	}
	res := []*proto.SqlCol{}
	for _, j := range cols {

		res = append(res, &proto.SqlCol{
			Name:      j.Name,
			Type:      j.Type,
			Precision: int64(j.Precision),
			Scale:     int64(j.Scale),
		})
	}
	return res, nil
}
func ToModelObjects(objs []*proto.Mock_Object) []models.Object {
	res := []models.Object{}
	for _, j := range objs {
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		if _, err := gz.Write(j.Data); err != nil {
			return nil
		}
		gz.Close()
		data := base64.StdEncoding.EncodeToString(b.Bytes())
		res = append(res, models.Object{
			Type: j.Type,
			Data: data,
		})
	}
	return res
}

func toProtoObjects(objs []models.Object) ([]*proto.Mock_Object, error) {
	res := []*proto.Mock_Object{}
	for _, j := range objs {
		data := []byte{}
		bin, err := base64.StdEncoding.DecodeString(j.Data)
		if err != nil {
			return nil, err
		}
		r := bytes.NewReader(bin)
		if r.Len() > 0 {
			gzr, err := gzip.NewReader(r)
			if err != nil {
				return nil, err
			}
			data, err = ioutil.ReadAll(gzr)
			if err != nil {
				return nil, err
			}
		}
		res = append(res, &proto.Mock_Object{
			Type: j.Type,
			Data: data,
		})
	}
	return res, nil
}



func Decode(doc []models.Mock) ([]*proto.Mock, error) {
	res := []*proto.Mock{}
	for _, j := range doc {
		mock := &proto.Mock{
			Version: string(j.Version),
			Name:    j.Name,
			Kind:    string(j.Kind),
		}
		switch j.Kind {
		case models.Mongo:
			spec := &models.MongoSpec{}
			err := j.Spec.Decode(spec)
			if err != nil {
				return res, fmt.Errorf("failed to decode the mongo spec of mock with name: %s.  error: %s", j.Name, err.Error())
			}
			mock.Spec = &proto.Mock_SpecSchema{
				Metadata: spec.Metadata,
				RequestHeader: &proto.MongoHeader{
					Length: spec.RequestHeader.Length,
					RequestId: spec.RequestHeader.RequestID,
					ResponseTo: spec.RequestHeader.ResponseTo,
					OpCode: int32(spec.RequestHeader.Opcode),
				},
				ResponseHeader: &proto.MongoHeader{
					Length: spec.ResponseHeader.Length,
					RequestId: spec.ResponseHeader.RequestID,
					ResponseTo: spec.ResponseHeader.ResponseTo,
					OpCode: int32(spec.ResponseHeader.Opcode),
				},
				// RequestMongoMessage: &proto.MongoMessage{
				// 	Header: &proto.MongoHeader{
				// 		Length:     spec.RequestMessage.Header.Length,
				// 		RequestId:  spec.RequestMessage.Header.RequestID,
				// 		ResponseTo: spec.RequestMessage.Header.ResponseTo,
				// 		OpCode:     int32(spec.RequestMessage.Header.Opcode),
				// 	},
				// 	FlagBits: int64(spec.RequestMessage.FlagBits),
				// 	Sections: spec.RequestMessage.Sections,
				// 	Checksum: int64(spec.RequestMessage.Checksum),
				// },
				// ResponseMongoMessage: &proto.MongoMessage{
				// 	Header: &proto.MongoHeader{
				// 		Length:     spec.ResponseMessage.Header.Length,
				// 		RequestId:  spec.ResponseMessage.Header.RequestID,
				// 		ResponseTo: spec.ResponseMessage.Header.ResponseTo,
				// 		OpCode:     int32(spec.ResponseMessage.Header.Opcode),
				// 	},
				// 	FlagBits: int64(spec.ResponseMessage.FlagBits),
				// 	Sections: spec.ResponseMessage.Sections,
				// 	Checksum: int64(spec.ResponseMessage.Checksum),
				// },
			}
			err = DecodeMongoMessage(spec, mock)
			if err!=nil {
				return res, err
			}
		case models.HTTP:
			spec := &models.HttpSpec{}
			err := j.Spec.Decode(spec)
			if err != nil {
				return res, fmt.Errorf("failed to decode the http spec of mock with name: %s.  error: %s", j.Name, err.Error())
			}
			obj, err := toProtoObjects(spec.Objects)
			if err != nil {
				return res, err
			}
			mock.Spec = &proto.Mock_SpecSchema{
				Metadata: spec.Metadata,
				Type:     string(models.HTTP),
				Req: &proto.HttpReq{
					Method:     string(spec.Request.Method),
					ProtoMajor: int64(spec.Request.ProtoMajor),
					ProtoMinor: int64(spec.Request.ProtoMinor),
					URL:        spec.Request.URL,
					Header:     utils.GetProtoMap(ToHttpHeader(spec.Request.Header)),
					Body:       spec.Request.Body,
					Form:       GetProtoFormData(spec.Request.Form),
					BodyData:   nil,
				},
				Objects: obj,
				Res: &proto.HttpResp{
					StatusCode:    int64(spec.Response.StatusCode),
					Header:        utils.GetProtoMap(ToHttpHeader(spec.Response.Header)),
					Body:          spec.Response.Body,
					StatusMessage: spec.Response.StatusMessage,
					ProtoMajor:    int64(spec.Response.ProtoMajor),
					ProtoMinor:    int64(spec.Request.ProtoMinor),
					Binary:        spec.Response.Binary,
					BodyData:      nil,
				},
				Mocks:      spec.Mocks,
				Assertions: utils.GetProtoMap(spec.Assertions),
				Created:    spec.Created,
			}
			if spec.Request.BodyType == string(models.BodyTypeBinary) {
				bin, err := base64.StdEncoding.DecodeString(spec.Request.Body)
				if err != nil {
					return nil, err
				}
				mock.Spec.Req.BodyData = bin
				mock.Spec.Req.Body = ""
			}
			if spec.Response.BodyType == string(models.BodyTypeBinary) {
				bin, err := base64.StdEncoding.DecodeString(spec.Response.Body)
				if err != nil {
					return nil, err
				}
				mock.Spec.Res.BodyData = bin
				mock.Spec.Res.Body = ""
			}
		case models.SQL:
			spec := &models.SQlSpec{}
			err := j.Spec.Decode(spec)
			if err != nil {
				return res, fmt.Errorf("failed to decode the sql spec of mock with name: %s.  error: %s", j.Name, err.Error())
			}
			cols, err := toProtoCols(spec.Table.Cols)
			if err != nil {
				return res, err
			}
			mock.Spec = &proto.Mock_SpecSchema{
				Type:     string(spec.Type),
				Metadata: spec.Metadata,
				Int:      int64(spec.Int),
				Err:      spec.Err,
			}
			if cols != nil {
				mock.Spec.Table = &proto.Table{
					Cols: cols,
					Rows: spec.Table.Rows,
				}
			}
			if spec.Err == nil {
				fmt.Println("\n\n\n nilnil", spec.Err, mock.Spec.Err)
			}

		case models.GENERIC:
			spec := &models.GenericSpec{}
			err := j.Spec.Decode(spec)
			if err != nil {
				return res, fmt.Errorf("failed to decode the generic spec of mock with name: %s.  error: %s", j.Name, err.Error())
			}
			obj, err := toProtoObjects(spec.Objects)
			if err != nil {
				return res, err
			}
			mock.Spec = &proto.Mock_SpecSchema{
				Metadata: spec.Metadata,
				Objects:  obj,
			}
		case models.GRPC_EXPORT:
			spec := &models.GrpcSpec{}
			err := j.Spec.Decode(spec)
			if err != nil {
				return res, fmt.Errorf("failed to decode the generic spec of mock with name: %s.  error: %s", j.Name, err.Error())
			}
			mock.Spec = &proto.Mock_SpecSchema{
				Metadata: spec.Metadata,
				GrpcRequest: &proto.GrpcReq{
					Body:   spec.Request.Body,
					Method: spec.Request.Method,
				},
				GrpcResp: &proto.GrpcResp{
					Body: spec.Response.Body,
					Err:  spec.Response.Err,
				},
				Type:       string(models.GRPC_EXPORT),
				Objects:    []*proto.Mock_Object{},
				Mocks:      spec.Mocks,
				Assertions: utils.GetProtoMap(spec.Assertions),
				Created:    spec.Created,
			}
			for _, j := range spec.Objects {
				mock.Spec.Objects = append(mock.Spec.Objects, &proto.Mock_Object{
					Type: j.Type,
					Data: []byte(j.Data),
				})
			}
		default:
			return res, fmt.Errorf("mock with name %s is not of a valid kind", j.Name)
		}
		res = append(res, mock)
	}
	return res, nil
}

func ToHttpHeader(mockHeader map[string]string) http.Header {
	header := http.Header{}
	for i, j := range mockHeader {
		match := pkg.IsTime(j)
		if match {
			//Values like "Tue, 17 Jan 2023 16:34:58 IST" should be considered as single element
			header[i] = []string{j}
			continue
		}
		header[i] = strings.Split(j, ",")
	}
	return header
}

func ToMockHeader(httpHeader http.Header) map[string]string {
	header := map[string]string{}
	for i, j := range httpHeader {
		header[i] = strings.Join(j, ",")
	}
	return header
}

func GetMockFormData(formData []*proto.FormData) []models.FormData {
	mockFormDataList := []models.FormData{}

	for _, j := range formData {
		mockFormDataList = append(mockFormDataList, models.FormData{
			Key:    j.Key,
			Values: j.Values,
			Paths:  j.Paths,
		})
	}
	return mockFormDataList
}

func GetProtoFormData(formData []models.FormData) []*proto.FormData {

	protoFormDataList := []*proto.FormData{}

	for _, j := range formData {
		protoFormDataList = append(protoFormDataList, &proto.FormData{
			Key:    j.Key,
			Values: j.Values,
			Paths:  j.Paths,
		})
	}
	return protoFormDataList
}
