#include "nids_resolver.h"

#include <map>
#include <vector>

static std::map< std::string, std::vector< std::pair<uint32_t, std::string> > > nids;

void init_nids()
{
	static bool inited = false;
	if (inited) return;
	inited = true;
	// TODO fill nids table
	std::vector< std::pair<uint32_t, std::string> > SceFios2 = {
		{0x1b9a575e, "sceFiosOpIsDone"},
	};
	nids["SceFios2"] = SceFios2;
}

std::string resolve(const char* lib_name, uint32_t nid)
{
	init_nids();
	const auto& it = nids.find(lib_name);
	if (it != nids.end()) {
		for (const auto& pair : (*it).second) {
			if (pair.first == nid) {
				return pair.second;
			}
		}
	}
	// default
	char buffer[0x100];
	snprintf(buffer, 0x100, "%s_0x%x", lib_name, nid);
	return buffer;
}