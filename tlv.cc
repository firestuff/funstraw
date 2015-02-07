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
			child.Encode(output);
		}
		size_t total_child_length = output->length() - header_start - sizeof(header);
		assert(total_child_length <= UINT16_MAX);
		header.value_length = htons((uint16_t)total_child_length);
		output->replace(header_start, sizeof(header), (char*)&header, sizeof(header));
	} else {
		output->append(value_);
	}
}

TLVNode* TLVNode::Decode(const std::string& input) {
	if (input.length() < sizeof(struct header)) {
		return NULL;
	}
	auto header = (struct header*)input.data();
	std::cerr << "[type=" << htons(header->type) << ", value_length=" << htons(header->value_length) << "]" << std::endl;
	if (input.length() < sizeof(*header) + htons(header->value_length)) {
		return NULL;
	}

	if (htons(header->type) & 0x8000) {
		// Container
		std::unique_ptr<TLVNode> container(new TLVNode(htons(header->type)));

		size_t cursor = sizeof(*header);
		while (cursor < input.length()) {
			auto next_header = (struct header*)(input.data() + cursor);
			if (cursor + sizeof(*next_header) + htons(next_header->value_length) > input.length()) {
				return NULL;
			}
			std::unique_ptr<TLVNode> child(Decode(input.substr(cursor)));
			if (!child.get()) {
				return NULL;
			}
			container->AppendChild(*child);
			cursor += sizeof(*next_header) + htons(next_header->value_length);
		}

		return container.release();
	} else {
		// Scalar
		return new TLVNode(htons(header->type), input.substr(sizeof(*header)));
	}
}

void TLVNode::AppendChild(const TLVNode& child) {
	assert(this->IsContainer());
	children_.push_back(child);
}

bool TLVNode::IsContainer() const {
	return type_ & 0x8000;
}
