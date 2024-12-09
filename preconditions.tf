#Advanced variable checking
resource "terraform_data" "input_checks" {
  lifecycle {

    #If controller initialization is enabled, controller needs to be deployed through this module as well.
    precondition {
      condition = (var.module_config.controller_initialization ?
        var.module_config.controller_deployment
        : true #If controller init not true, simply pass the check.
      )
      error_message = "If controller_initialization is enabled, controller also needs to be deployed. If you are only trying to initialize an existing copilot instance, call the copilot submodule directly."
    }

    #If copilot is enabled, controller needs to be deployed through this module as well.
    precondition {
      condition = (var.module_config.copilot_deployment ?
        var.module_config.controller_deployment
        : true #If copilot deployment not true, simply pass the check.
      )
      error_message = "If copilot_deployment is enabled, controller also needs to be deployed through this module. If you are only trying to deploy copilot, call the copilot submodule directly."
    }


    #If copilot initialization is enabled, copilot needs to be deployed through this module as well.
    precondition {
      condition = (var.module_config.copilot_initialization ?
        var.module_config.copilot_deployment
        : true #If copilot init not true, simply pass the check.
      )
      error_message = "If copilot_initialization is enabled, copilot also needs to be deployed through this module. If you are only trying to initialize an existing copilot instance, call the copilot submodule directly."
    }
  }
}
