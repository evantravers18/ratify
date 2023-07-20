// Code generated by protoc-gen-go. DO NOT EDIT.
// source: ratify/proto/v2/verifier.proto

package verifier

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Request for VerifyReference
type VerifyReferenceRequest struct {
	// The subject of the artifact.
	Subject string `protobuf:"bytes,1,opt,name=subject,proto3" json:"subject,omitempty"`
	// The artifact to be evaluated.
	Reference string `protobuf:"bytes,2,opt,name=reference,proto3" json:"reference,omitempty"`
	// Optional. Custom to the verifier plugin. Can be used to further customize the artifact verification logic.
	Configuration        *_struct.Struct `protobuf:"bytes,3,opt,name=configuration,proto3" json:"configuration,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *VerifyReferenceRequest) Reset()         { *m = VerifyReferenceRequest{} }
func (m *VerifyReferenceRequest) String() string { return proto.CompactTextString(m) }
func (*VerifyReferenceRequest) ProtoMessage()    {}
func (*VerifyReferenceRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_fa56c7c0fa1b1fbb, []int{0}
}

func (m *VerifyReferenceRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyReferenceRequest.Unmarshal(m, b)
}
func (m *VerifyReferenceRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyReferenceRequest.Marshal(b, m, deterministic)
}
func (m *VerifyReferenceRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyReferenceRequest.Merge(m, src)
}
func (m *VerifyReferenceRequest) XXX_Size() int {
	return xxx_messageInfo_VerifyReferenceRequest.Size(m)
}
func (m *VerifyReferenceRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyReferenceRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyReferenceRequest proto.InternalMessageInfo

func (m *VerifyReferenceRequest) GetSubject() string {
	if m != nil {
		return m.Subject
	}
	return ""
}

func (m *VerifyReferenceRequest) GetReference() string {
	if m != nil {
		return m.Reference
	}
	return ""
}

func (m *VerifyReferenceRequest) GetConfiguration() *_struct.Struct {
	if m != nil {
		return m.Configuration
	}
	return nil
}

// Response for VerifyReference
type VerifyReferenceResponse struct {
	// The name of the verifier which evaluated the artifact.
	VerifierName string `protobuf:"bytes,1,opt,name=verifierName,proto3" json:"verifierName,omitempty"`
	// The subject of the artifact.
	Subject string `protobuf:"bytes,2,opt,name=subject,proto3" json:"subject,omitempty"`
	// The artifact under evaluation.
	Reference string `protobuf:"bytes,3,opt,name=reference,proto3" json:"reference,omitempty"`
	// Whether the artifact passed validation
	Valid                bool     `protobuf:"varint,4,opt,name=valid,proto3" json:"valid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VerifyReferenceResponse) Reset()         { *m = VerifyReferenceResponse{} }
func (m *VerifyReferenceResponse) String() string { return proto.CompactTextString(m) }
func (*VerifyReferenceResponse) ProtoMessage()    {}
func (*VerifyReferenceResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_fa56c7c0fa1b1fbb, []int{1}
}

func (m *VerifyReferenceResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyReferenceResponse.Unmarshal(m, b)
}
func (m *VerifyReferenceResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyReferenceResponse.Marshal(b, m, deterministic)
}
func (m *VerifyReferenceResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyReferenceResponse.Merge(m, src)
}
func (m *VerifyReferenceResponse) XXX_Size() int {
	return xxx_messageInfo_VerifyReferenceResponse.Size(m)
}
func (m *VerifyReferenceResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyReferenceResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyReferenceResponse proto.InternalMessageInfo

func (m *VerifyReferenceResponse) GetVerifierName() string {
	if m != nil {
		return m.VerifierName
	}
	return ""
}

func (m *VerifyReferenceResponse) GetSubject() string {
	if m != nil {
		return m.Subject
	}
	return ""
}

func (m *VerifyReferenceResponse) GetReference() string {
	if m != nil {
		return m.Reference
	}
	return ""
}

func (m *VerifyReferenceResponse) GetValid() bool {
	if m != nil {
		return m.Valid
	}
	return false
}

func init() {
	proto.RegisterType((*VerifyReferenceRequest)(nil), "verifier.VerifyReferenceRequest")
	proto.RegisterType((*VerifyReferenceResponse)(nil), "verifier.VerifyReferenceResponse")
}

func init() { proto.RegisterFile("ratify/proto/v2/verifier.proto", fileDescriptor_fa56c7c0fa1b1fbb) }

var fileDescriptor_fa56c7c0fa1b1fbb = []byte{
	// 295 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x91, 0xcb, 0x4a, 0xc3, 0x40,
	0x14, 0x86, 0x99, 0xd6, 0x4b, 0x3b, 0xde, 0x60, 0x10, 0x1b, 0x4a, 0x91, 0xd8, 0x55, 0x56, 0x33,
	0x10, 0x57, 0x22, 0x6e, 0x7c, 0x00, 0x91, 0x08, 0x59, 0xb8, 0x4b, 0xd2, 0x93, 0x74, 0x24, 0x99,
	0x89, 0x73, 0x09, 0xf6, 0x19, 0x5c, 0xf8, 0xca, 0xd2, 0x24, 0xa3, 0xb6, 0x95, 0x2e, 0xff, 0x7f,
	0x3e, 0x86, 0xef, 0x9c, 0x83, 0xaf, 0x55, 0x62, 0x78, 0xbe, 0x62, 0xb5, 0x92, 0x46, 0xb2, 0x26,
	0x64, 0x0d, 0x28, 0x9e, 0x73, 0x50, 0xb4, 0x6d, 0xc8, 0xc8, 0xe5, 0xe9, 0xac, 0x90, 0xb2, 0x28,
	0xa1, 0x23, 0x53, 0x9b, 0x33, 0x6d, 0x94, 0xcd, 0x4c, 0xc7, 0xcd, 0xbf, 0x10, 0xbe, 0x8a, 0xd7,
	0xe8, 0x2a, 0x82, 0x1c, 0x14, 0x88, 0x0c, 0x22, 0x78, 0xb7, 0xa0, 0x0d, 0xf1, 0xf0, 0xb1, 0xb6,
	0xe9, 0x1b, 0x64, 0xc6, 0x43, 0x3e, 0x0a, 0xc6, 0x91, 0x8b, 0x64, 0x86, 0xc7, 0xca, 0xd1, 0xde,
	0xa0, 0x7d, 0xfb, 0x2d, 0xc8, 0x03, 0x3e, 0xcb, 0xa4, 0xc8, 0x79, 0x61, 0xd7, 0x8e, 0x52, 0x78,
	0x43, 0x1f, 0x05, 0x27, 0xe1, 0x84, 0x76, 0x22, 0xd4, 0x89, 0xd0, 0x97, 0x56, 0x24, 0xda, 0xa4,
	0xe7, 0x9f, 0x08, 0x4f, 0x76, 0x8c, 0x74, 0x2d, 0x85, 0x06, 0x32, 0xc7, 0xa7, 0x6e, 0xae, 0xa7,
	0xa4, 0x82, 0xde, 0x6b, 0xa3, 0xfb, 0xab, 0x3d, 0xd8, 0xa3, 0x3d, 0xdc, 0xd6, 0xbe, 0xc4, 0x87,
	0x4d, 0x52, 0xf2, 0x85, 0x77, 0xe0, 0xa3, 0x60, 0x14, 0x75, 0x21, 0x5c, 0xe2, 0xf3, 0xb8, 0xff,
	0xfd, 0xb9, 0xb4, 0x05, 0x17, 0x24, 0xc6, 0x17, 0x5b, 0x7a, 0xc4, 0xa7, 0x3f, 0xdb, 0xff, 0x7f,
	0x97, 0xd3, 0x9b, 0x3d, 0x44, 0x37, 0xdb, 0xe3, 0xfd, 0xeb, 0x5d, 0xc1, 0xcd, 0xd2, 0xa6, 0x34,
	0x93, 0x15, 0x5b, 0x00, 0xd7, 0x65, 0x92, 0x6a, 0xd6, 0xdf, 0x19, 0x3e, 0x6a, 0x50, 0xbc, 0x02,
	0x61, 0x92, 0x72, 0xf7, 0xe8, 0xe9, 0x51, 0x5b, 0xdd, 0x7e, 0x07, 0x00, 0x00, 0xff, 0xff, 0xc4,
	0x14, 0x1c, 0x1e, 0x17, 0x02, 0x00, 0x00,
}