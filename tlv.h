#include <stdint.h>

#include <list>
#include <string>

class TLVNode {
	public:
		TLVNode(const uint16_t type);
		TLVNode(const uint16_t type, const std::string value);
		~TLVNode();

		static std::unique_ptr<TLVNode> Decode(const std::string& input);

		void AppendChild(TLVNode* child);

		TLVNode* FindChild(const uint16_t type) const;
		void Encode(std::string* output) const;
		bool IsContainer() const;
		uint16_t GetType() const;
		const std::string& GetValue() const;
		const std::list<TLVNode*>& GetChildren() const;

	private:
		const uint16_t type_;
		const std::string value_;
		std::list<TLVNode*> children_;
};
