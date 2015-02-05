#include "tlv.h"

TLVNode::TLVNode(const uint16_t type)
	: type_(type) {}

TLVNode::TLVNode(const uint16_t type, const std::string value)
	: type_(type),
	  value_(value) {}
