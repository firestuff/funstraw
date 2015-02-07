#include <stdint.h>

#include <list>
#include <string>

class TLVNode {
	public:
		TLVNode(const uint16_t type);
		TLVNode(const uint16_t type, const std::string value);

		static TLVNode* Decode(const std::string& input);

		void AppendChild(const TLVNode& child);

		void Encode(std::string *output) const;
		bool IsContainer() const;

	private:
		const uint16_t type_;
		const std::string value_;
		std::list<TLVNode> children_;
};
