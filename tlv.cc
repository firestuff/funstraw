#include <cassert>
#include <iostream>

#include "tlv.h"

struct header {
	uint16_t type;
	uint16_t value_length;
};

TLVNode::TLVNode(const uint16_t type)
	: type_(type) {}

TLVNode::TLVNode(const uint16_t type, const std::string value)
	: type_(type),
	  value_(value) {}

TLVNode::~TLVNode() {
	for (auto child : children_) {
		delete child;
	}
}

void TLVNode::Encode(std::string *output) const {
	assert(value_.length() <= UINT16_MAX);
	struct header header = {
		.type = htons(type_),
		.value_length = htons((uint16_t)value_.length()),
	};
	size_t header_start = output->length();
	output->append((char*)&header, sizeof(header));

	if (IsContainer()) {
		for (auto child : children_) {
			child->Encode(output);
		}
		size_t total_child_length = output->length() - header_start - sizeof(header);
		assert(total_child_length <= UINT16_MAX);
		header.value_length = htons((uint16_t)total_child_length);
		output->replace(header_start, sizeof(header), (char*)&header, sizeof(header));
	} else {
		output->append(value_);
	}
}

std::unique_ptr<TLVNode> TLVNode::Decode(const std::string& input) {
	if (input.length() < sizeof(struct header)) {
		return nullptr;
	}
	auto header = (struct header*)input.data();
	if (input.length() < sizeof(*header) + htons(header->value_length)) {
		return nullptr;
	}

	if (htons(header->type) & 0x8000) {
		// Container
		std::unique_ptr<TLVNode> container(new TLVNode(htons(header->type)));

		size_t cursor = sizeof(*header);
		while (cursor < input.length()) {
			auto next_header = (struct header*)(input.data() + cursor);
			size_t sub_length = sizeof(*next_header) + htons(next_header->value_length);
			if (cursor + sub_length > input.length()) {
				return nullptr;
			}
			std::unique_ptr<TLVNode> child(Decode(input.substr(cursor, sub_length)));
			if (!child.get()) {
				return nullptr;
			}
			container->AppendChild(child.release());
			cursor += sub_length;
		}

		return container;
	} else {
		// Scalar
		return std::unique_ptr<TLVNode>(new TLVNode(htons(header->type), input.substr(sizeof(*header), htons(header->value_length))));
	}
}

void TLVNode::AppendChild(TLVNode* child) {
	assert(this->IsContainer());
	children_.push_back(child);
}

TLVNode* TLVNode::FindChild(const uint16_t type) const {
	assert(this->IsContainer());
	for (auto child : children_) {
		if (child->GetType() == type) {
			return child;
		}
	}
	return nullptr;
}

bool TLVNode::IsContainer() const {
	return type_ & 0x8000;
}

uint16_t TLVNode::GetType() const {
	return type_;
}

const std::string& TLVNode::GetValue() const {
	assert(!this->IsContainer());
	return value_;
}
