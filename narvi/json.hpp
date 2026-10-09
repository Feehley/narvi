// json.hpp -- tiny recursive-descent JSON parser.
//
// moria hand-emits JSON and links no JSON library; narvi keeps the same
// zero-JSON-dependency stance and parses moria's (well-formed) output with this.
// Numbers are kept as their source token so offsets/sizes read back as exact
// unsigned integers rather than via double.
#pragma once
#include <cstdint>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace narvi {

struct Json {
    enum class T { Null, Bool, Num, Str, Arr, Obj };
    T t = T::Null;
    bool b = false;
    std::string num;   // raw numeric token
    std::string str;
    std::vector<Json> arr;
    std::map<std::string, Json> obj;

    bool is_obj() const { return t == T::Obj; }
    bool is_arr() const { return t == T::Arr; }

    const Json* find(const std::string& key) const {
        if (t != T::Obj) return nullptr;
        auto it = obj.find(key);
        return it == obj.end() ? nullptr : &it->second;
    }
    uint64_t as_u64() const { return num.empty() ? 0 : std::strtoull(num.c_str(), nullptr, 10); }
    std::string as_str() const { return str; }

    // Convenience getters with defaults.
    uint64_t u64(const std::string& key, uint64_t def = 0) const {
        auto* v = find(key); return v ? v->as_u64() : def;
    }
    std::string s(const std::string& key, const std::string& def = "") const {
        auto* v = find(key); return v ? v->str : def;
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::string& src) : s_(src) {}
    Json parse() {
        Json v = value();
        ws();
        if (i_ != s_.size()) fail("trailing data");
        return v;
    }

private:
    const std::string& s_;
    size_t i_ = 0;
    int depth_ = 0;

    struct DepthGuard {
        int& counter;
        DepthGuard(int& d, const JsonParser* self) : counter(d) {
            if (++counter > 1024) self->fail("nesting too deep");
        }
        ~DepthGuard() { --counter; }
    };

    [[noreturn]] void fail(const std::string& m) const {
        throw std::runtime_error("json: " + m + " at offset " + std::to_string(i_));
    }
    void ws() { while (i_ < s_.size() && (s_[i_]==' '||s_[i_]=='\t'||s_[i_]=='\n'||s_[i_]=='\r')) ++i_; }
    char peek() { ws(); return i_ < s_.size() ? s_[i_] : '\0'; }

    Json value() {
        DepthGuard g(depth_, this);
        char c = peek();
        switch (c) {
            case '{': return object();
            case '[': return array();
            case '"': { Json j; j.t = Json::T::Str; j.str = str(); return j; }
            case 't': case 'f': return boolean();
            case 'n': lit("null"); return Json{};
            default:  return number();
        }
    }
    Json object() {
        Json j; j.t = Json::T::Obj; ++i_; // {
        if (peek() == '}') { ++i_; return j; }
        for (;;) {
            if (peek() != '"') fail("expected key");
            std::string k = str();
            if (peek() != ':') fail("expected ':'");
            ++i_;
            j.obj[k] = value();
            char c = peek();
            if (c == ',') { ++i_; continue; }
            if (c == '}') { ++i_; break; }
            fail("expected ',' or '}'");
        }
        return j;
    }
    Json array() {
        Json j; j.t = Json::T::Arr; ++i_; // [
        if (peek() == ']') { ++i_; return j; }
        for (;;) {
            j.arr.push_back(value());
            char c = peek();
            if (c == ',') { ++i_; continue; }
            if (c == ']') { ++i_; break; }
            fail("expected ',' or ']'");
        }
        return j;
    }
    Json boolean() {
        Json j; j.t = Json::T::Bool;
        if (s_.compare(i_, 4, "true") == 0) { j.b = true; i_ += 4; }
        else if (s_.compare(i_, 5, "false") == 0) { j.b = false; i_ += 5; }
        else fail("bad literal");
        return j;
    }
    void lit(const char* l) {
        size_t n = 0; while (l[n]) ++n;
        if (s_.compare(i_, n, l) != 0) fail("bad literal");
        i_ += n;
    }
    Json number() {
        size_t start = i_;
        if (peek() == '-') ++i_;
        while (i_ < s_.size()) {
            char c = s_[i_];
            if ((c>='0'&&c<='9')||c=='+'||c=='-'||c=='.'||c=='e'||c=='E') ++i_; else break;
        }
        if (i_ == start) fail("bad number");
        Json j; j.t = Json::T::Num; j.num = s_.substr(start, i_ - start);
        return j;
    }
    std::string str() {
        ws();
        if (s_[i_] != '"') fail("expected string");
        ++i_;
        std::string out;
        while (i_ < s_.size()) {
            char c = s_[i_++];
            if (c == '"') return out;
            if (c == '\\') {
                char e = s_[i_++];
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'n': out += '\n'; break;
                    case 't': out += '\t'; break;
                    case 'r': out += '\r'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'u': {
                        unsigned cp = (unsigned)std::strtoul(s_.substr(i_, 4).c_str(), nullptr, 16);
                        i_ += 4;
                        if (cp < 0x80) out += (char)cp;
                        else if (cp < 0x800) { out += (char)(0xC0|(cp>>6)); out += (char)(0x80|(cp&0x3F)); }
                        else { out += (char)(0xE0|(cp>>12)); out += (char)(0x80|((cp>>6)&0x3F)); out += (char)(0x80|(cp&0x3F)); }
                        break;
                    }
                    default: out += e;
                }
            } else out += c;
        }
        fail("unterminated string");
    }
};

inline Json json_parse(const std::string& src) { return JsonParser(src).parse(); }

// --- output helpers (mirroring moria's hand-emitted style) ---
inline void json_escape(std::string& o, const std::string& s) {
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default: o += c;
        }
    }
}

}  // namespace narvi
