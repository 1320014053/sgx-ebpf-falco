#include "../plugin/detectors.hpp"
#include <cassert>

int main() {
    std::vector<rz::Json> alerts;
    rz::RavenStream detector([&](const rz::Json& row) { alerts.push_back(row); });
    rz::Json event = {{"event_id","old"},{"ts",100},{"event_type","file_modify"},
                      {"pid",1},{"file_path","/root/retention-idle"},{"file_op","write"}};
    detector.event(event);
    detector.advance(701);
    event.update(rz::Json{{"event_id","read"},{"ts",150},{"event_type","file_access"},{"file_op","open"}});
    detector.event(event);
    detector.event(event);
    assert(alerts.size()==1);
    const auto& row = alerts.front();
    assert(row["meta"]["retention"]["reason"]=="time" && row["meta"]["retention"]["start"]==101);
    const auto& edges = row["reconstruction"]["graph"]["edges"];
    assert(edges.size()==1 && edges[0]["type"]=="accessed" && edges[0]["event_ids"]==rz::Json::array({"read"}));

    std::vector<rz::Json> late_alerts;
    rz::RavenStream late([&](const rz::Json& record) { late_alerts.push_back(record); });
    late.event({{"event_id","old"},{"ts",101},{"event_type","file_modify"},{"pid",1},{"file_path","/tmp/old"}});
    late.event({{"event_id","marker"},{"ts",700},{"event_type","process_exec"},{"pid",2},{"exe","/bin/date"}});
    late.event({{"event_id","service"},{"ts",600},{"event_type","process_exec"},{"pid",3},{"exe","/usr/bin/nginx"}});
    late.advance(702);
    late.event({{"event_id","shell"},{"ts",601},{"event_type","process_exec"},{"pid",4},{"ppid",3},{"exe","/bin/sh"}});
    assert(late_alerts.size()==1 && late_alerts[0]["rule"]=="server_spawns_shell");

    std::vector<std::string> states;
    rz::RavenStream review([&](const rz::Json& record) { states.push_back(record.at("state")); });
    review.event({{"ts",100},{"pid",3},{"exe","/usr/sbin/nginx"}});
    review.event({{"ts",101},{"pid",4},{"ppid",3},{"exe","/bin/sh"}});
    review.event({{"ts",110},{"pid",4},{"event_type","net_connect"},{"dst_ip","127.0.0.1"}});
    review.advance(162);
    review.event({{"ts",150},{"pid",5},{"exe","/bin/ls"}});
    assert(states == std::vector<std::string>{"active"});
    review.event({{"ts",161},{"pid",4},{"ppid",3},{"exe","/usr/bin/true"}});
    review.advance(0, true);
    assert(states == std::vector<std::string>{"active"});
}
