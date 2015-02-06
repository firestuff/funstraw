#include <cassert>

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

void TLVNode::Encode(std::string *output) {
	assert(value_.length() <= UINT16_MAX);
	struct header header = {
		.type = type_,
		.value_length = (uint16_t)value_.length(),
	};
	size_t header_start = output->length();
	output->append((char*)&header, sizeof(header));

	if (IsContainer()) {
		for (auto child : children_) {
			child.Encode(output);
		}
		size_t total_child_length = output->length() - header_start - sizeof(header);
		assert(total_child_length <= UINT16_MAX);
		header.value_length = (uint16_t)total_child_length;
		output->replace(header_start, sizeof(header), (char*)&header, sizeof(header));
	}
}

bool TLVNode::IsContainer() {
	return type_ & 0x8000;
}
