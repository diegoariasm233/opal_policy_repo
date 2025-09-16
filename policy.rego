package play

#import rego.v1

#package authz
#import future.keywords.if

# Obtener el token OAuth de Entra ID
#oauth_token if {
#    oauth_token := data.oauth.token.token # <-- accedes al token así
#    trace(sprintf("Token de acceso: %s", [oauth_token]))  # Esto imprimirá el token para verificar que está siendo asignado correctamente
#}

default allow := false

# ---- Permisos de ejemplo (constante) ----
# Puedes añadir recursos y acciones aquí.
# Cada acción lista los grupos habilitados.
permissions := {
  "buttonDerivateTable": {
    "get":  {"groups": {"EDITAR_OPERACIONES", "Consultar_Plataforma"}},
    "post": {"groups": {"S_EXAMPLE_SECURITY_GRUP"}}
  },
  "invoices": {
    "get":  {"groups": {"Consultar_Plataforma", "S_EXAMPLE_SECURITY_GRUP", "EDITAR_OPERACIONES"}},
    "post": {"groups": {"S_EXAMPLE_SECURITY_GRUP"}},
    "delete": {"groups": {"S_EXAMPLE_SECURITY_GRUP"}}
  }
}

user_groups := { g |
  some i
  input.groups_data[i].displayName == g
}

valid_input {
  input.action != ""
  input.resource != ""
}

allow {
  valid_input
  perms := permissions[input.resource][input.action]
  some g
  g := user_groups[_]
  perms.groups[g]
}

#allow if{
 #  input.request.parsed_token.payload.groups[_] == "devops_team"
  #    some i
   # io.jwt.decode_verify(input.token, {"keys": data.jwks.keys})
    #decoded := io.jwt.decode(input.token)
   # decoded.payload.groups[i] == "devops_team"
#}

#user_object_id[user_email] := object_id if {
#    response := http.send({
#        "method": "GET",
#        "url": sprintf("https://graph.microsoft.com/v1.0/users?$filter=mail eq '%s'", [user_email]),
#        "headers": {
#            "Authorization": sprintf("Bearer %s", [data.oauth.token.token]),
#            "Content-Type": "application/json"
#        }
#    })
#    count(response.body.value) > 0
#    object_id := response.body.value[0].id
#}

# Obtener grupos de un usuario de manera segura
#user_groups[user_email] contains group if {
#    object_id := user_object_id[user_email]
#    response := http.send({
#        "method": "GET",
#        "url": sprintf("https://graph.microsoft.com/v1.0/users/%s/memberOf", [object_id]),
#        "headers": {
#            "Authorization": sprintf("Bearer %s", [data.oauth.token.token]),
#            "Content-Type": "application/json"
#        }
#    })
#    count(response.body.value) > 0
#    group := [g.displayName]
#}


# Verifica si el grupo del usuario tiene acceso al proceso
#group_has_access_to_process[process_id] contains true if {
#    # Asegurar que el email del usuario proviene de input
#    user_email := input.user.mail
#    group := user_groups[user_email]
#    trace(sprintf("Grupo del usuario: %s", [group]))  # Asegúrate de que el grupo está correctamente asignado
#    group in data.process_group[process_id]  # Verifica que el grupo esté listado para el proceso
#}

# Verifica si el proceso puede llamar a otro proceso (herencia de permisos)
#process_inherits_access[process_id] contains true if {
#    some parent_process_id
#    parent_process_id = data.process_relation[process_id][_]
#    trace(sprintf("Proceso padre: %s", [parent_process_id]))  # Verifica que el proceso padre esté correctamente asignado
#    parent_process_id in data.processes  # Asegúrate de que el proceso padre existe
#}

# Permiso basado en relación para tareas con `status=error`
#allow if {
#    user_email := input.user.mail
#    trace(sprintf("Usuario: %s", [user_email]))

 #   process_id := input.process_id
 #   trace(sprintf("Proceso ID: %s", [process_id]))

 #   task_id := data.process_task[process_id]
 #   trace(sprintf("Tarea ID: %s", [task_id]))

 #   data.tasks[task_id].status == "error"
 #   trace("Tarea en estado 'error'")

 #   allow_process_access[process_id]
 #   trace(sprintf("Acceso al proceso %s permitido", [process_id]))

 #   input.user.country == data.processes[process_id].country
 #   trace(sprintf("Validación de país: Usuario '%s' vs Proceso '%s'", [input.user.country, data.processes[process_id].country]))  # Imprime los valores para ver qué está pasando

#}

# Separamos las reglas para acceso por grupo o herencia
#allow_process_access[process_id] contains true if {
#    user_email := input.user.mail
#    trace(sprintf("Email del usuario: %s", [user_email]))  # Esto imprimirá el email del usuario
#    user_email == "expected_email@domain.com"  # Puedes verificar si el email está correcto
#    process_id := input.process_id
#    trace(sprintf("ID del proceso: %s", [process_id]))  # Imprime el ID del proceso
#    process_id == "expected_process_id"  # Puedes verificar si el proceso está bien definido
 #   group_has_access_to_process[process_id]
#}

#allow_process_access[process_id] contains true if {
#    process_inherits_access[process_id]
#}