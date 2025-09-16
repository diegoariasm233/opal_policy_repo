package play

default allow := false
permissions := {
	"buttonDerivateTable": {
		"get": {"groups": {"EDITAR_OPERACIONES", "Consultar_Plataforma"}},
		"post": {"groups": {"S_EXAMPLE_SECURITY_GRUP"}},
	},
	"invoices": {
		"get": {"groups": {"Consultar_Plataforma", "S_EXAMPLE_SECURITY_GRUP", "EDITAR_OPERACIONES"}},
		"post": {"groups": {"S_EXAMPLE_SECURITY_GRUP"}},
		"delete": {"groups": {"S_EXAMPLE_SECURITY_GRUP"}},
	},
}
allow if {
	input.action != ""
	input.resource != ""
	input.groups_data != ""
	perms := permissions[input.resource][input.action]
	some i
	grp := input.groups_data[i].displayName
	perms.groups[grp]
}