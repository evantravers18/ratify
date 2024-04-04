//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The Ratify Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package unversioned

import ()

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateStore) DeepCopyInto(out *CertificateStore) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateStore.
func (in *CertificateStore) DeepCopy() *CertificateStore {
	if in == nil {
		return nil
	}
	out := new(CertificateStore)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateStoreList) DeepCopyInto(out *CertificateStoreList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CertificateStore, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateStoreList.
func (in *CertificateStoreList) DeepCopy() *CertificateStoreList {
	if in == nil {
		return nil
	}
	out := new(CertificateStoreList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateStoreSpec) DeepCopyInto(out *CertificateStoreSpec) {
	*out = *in
	in.Parameters.DeepCopyInto(&out.Parameters)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateStoreSpec.
func (in *CertificateStoreSpec) DeepCopy() *CertificateStoreSpec {
	if in == nil {
		return nil
	}
	out := new(CertificateStoreSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateStoreStatus) DeepCopyInto(out *CertificateStoreStatus) {
	*out = *in
	if in.LastFetchedTime != nil {
		in, out := &in.LastFetchedTime, &out.LastFetchedTime
		*out = (*in).DeepCopy()
	}
	in.Properties.DeepCopyInto(&out.Properties)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateStoreStatus.
func (in *CertificateStoreStatus) DeepCopy() *CertificateStoreStatus {
	if in == nil {
		return nil
	}
	out := new(CertificateStoreStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeyManagementProvider) DeepCopyInto(out *KeyManagementProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeyManagementProvider.
func (in *KeyManagementProvider) DeepCopy() *KeyManagementProvider {
	if in == nil {
		return nil
	}
	out := new(KeyManagementProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeyManagementProviderList) DeepCopyInto(out *KeyManagementProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]KeyManagementProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeyManagementProviderList.
func (in *KeyManagementProviderList) DeepCopy() *KeyManagementProviderList {
	if in == nil {
		return nil
	}
	out := new(KeyManagementProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeyManagementProviderSpec) DeepCopyInto(out *KeyManagementProviderSpec) {
	*out = *in
	in.Parameters.DeepCopyInto(&out.Parameters)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeyManagementProviderSpec.
func (in *KeyManagementProviderSpec) DeepCopy() *KeyManagementProviderSpec {
	if in == nil {
		return nil
	}
	out := new(KeyManagementProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeyManagementProviderStatus) DeepCopyInto(out *KeyManagementProviderStatus) {
	*out = *in
	if in.LastFetchedTime != nil {
		in, out := &in.LastFetchedTime, &out.LastFetchedTime
		*out = (*in).DeepCopy()
	}
	in.Properties.DeepCopyInto(&out.Properties)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeyManagementProviderStatus.
func (in *KeyManagementProviderStatus) DeepCopy() *KeyManagementProviderStatus {
	if in == nil {
		return nil
	}
	out := new(KeyManagementProviderStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PluginSource) DeepCopyInto(out *PluginSource) {
	*out = *in
	in.AuthProvider.DeepCopyInto(&out.AuthProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PluginSource.
func (in *PluginSource) DeepCopy() *PluginSource {
	if in == nil {
		return nil
	}
	out := new(PluginSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Policy) DeepCopyInto(out *Policy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Policy.
func (in *Policy) DeepCopy() *Policy {
	if in == nil {
		return nil
	}
	out := new(Policy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyList) DeepCopyInto(out *PolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Policy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyList.
func (in *PolicyList) DeepCopy() *PolicyList {
	if in == nil {
		return nil
	}
	out := new(PolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicySpec) DeepCopyInto(out *PolicySpec) {
	*out = *in
	in.Parameters.DeepCopyInto(&out.Parameters)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicySpec.
func (in *PolicySpec) DeepCopy() *PolicySpec {
	if in == nil {
		return nil
	}
	out := new(PolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyStatus) DeepCopyInto(out *PolicyStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyStatus.
func (in *PolicyStatus) DeepCopy() *PolicyStatus {
	if in == nil {
		return nil
	}
	out := new(PolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Store) DeepCopyInto(out *Store) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Store.
func (in *Store) DeepCopy() *Store {
	if in == nil {
		return nil
	}
	out := new(Store)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StoreList) DeepCopyInto(out *StoreList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Store, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StoreList.
func (in *StoreList) DeepCopy() *StoreList {
	if in == nil {
		return nil
	}
	out := new(StoreList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StoreSpec) DeepCopyInto(out *StoreSpec) {
	*out = *in
	if in.Source != nil {
		in, out := &in.Source, &out.Source
		*out = new(PluginSource)
		(*in).DeepCopyInto(*out)
	}
	in.Parameters.DeepCopyInto(&out.Parameters)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StoreSpec.
func (in *StoreSpec) DeepCopy() *StoreSpec {
	if in == nil {
		return nil
	}
	out := new(StoreSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StoreStatus) DeepCopyInto(out *StoreStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StoreStatus.
func (in *StoreStatus) DeepCopy() *StoreStatus {
	if in == nil {
		return nil
	}
	out := new(StoreStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Verifier) DeepCopyInto(out *Verifier) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Verifier.
func (in *Verifier) DeepCopy() *Verifier {
	if in == nil {
		return nil
	}
	out := new(Verifier)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VerifierList) DeepCopyInto(out *VerifierList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Verifier, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VerifierList.
func (in *VerifierList) DeepCopy() *VerifierList {
	if in == nil {
		return nil
	}
	out := new(VerifierList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VerifierSpec) DeepCopyInto(out *VerifierSpec) {
	*out = *in
	if in.Source != nil {
		in, out := &in.Source, &out.Source
		*out = new(PluginSource)
		(*in).DeepCopyInto(*out)
	}
	in.Parameters.DeepCopyInto(&out.Parameters)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VerifierSpec.
func (in *VerifierSpec) DeepCopy() *VerifierSpec {
	if in == nil {
		return nil
	}
	out := new(VerifierSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VerifierStatus) DeepCopyInto(out *VerifierStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VerifierStatus.
func (in *VerifierStatus) DeepCopy() *VerifierStatus {
	if in == nil {
		return nil
	}
	out := new(VerifierStatus)
	in.DeepCopyInto(out)
	return out
}
