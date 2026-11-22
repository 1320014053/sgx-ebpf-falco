#include <plugin/plugin_api.h>
#include <type_traits>

#define PLUGIN_SYMBOLS(X) \
    X(get_required_api_version) X(get_version) X(get_name) X(get_description) X(get_contact) \
    X(get_init_schema) X(get_last_error) X(init) X(destroy) X(set_config) X(get_metrics) \
    X(get_required_event_schema_version) X(get_extract_event_types) X(get_extract_event_sources) \
    X(get_fields) X(extract_fields) X(get_parse_event_types) X(get_parse_event_sources) \
    X(parse_event) X(capture_open) X(capture_close) X(get_async_event_sources) \
    X(get_async_events) X(set_async_event_handler) X(dump_state)

#define DECLARE(name) extern "C" std::remove_pointer_t<decltype(plugin_api::name)> plugin_##name;
PLUGIN_SYMBOLS(DECLARE)
#undef DECLARE

const plugin_api* container_api() {
    static const plugin_api api = [] {
        plugin_api out{};
#define ASSIGN(name) out.name = plugin_##name;
        PLUGIN_SYMBOLS(ASSIGN)
#undef ASSIGN
        return out;
    }();
    return &api;
}
