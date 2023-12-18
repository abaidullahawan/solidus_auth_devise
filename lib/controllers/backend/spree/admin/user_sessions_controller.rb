# frozen_string_literal: true

class Spree::Admin::UserSessionsController < Devise::SessionsController
  helper 'spree/base'

  include Spree::Core::ControllerHelpers::Auth
  include Spree::Core::ControllerHelpers::Common
  include Spree::Core::ControllerHelpers::Store

  helper 'spree/admin/navigation'
  layout 'spree/layouts/admin'

  def create
    if valid_credentials?
      # User provided valid credentials
      authenticate_spree_user!
      sign_in(@spree_user)
      respond_to do |format|
        format.html do
          flash[:success] = I18n.t('spree.logged_in_succesfully')
          redirect_back_or_default(after_sign_in_path_for(spree_current_user))
        end
        format.js { render success_json }
      end
    else
      # User provided invalid credentials
      respond_to do |format|
        format.html do
          flash.now[:error] = @flash_error
          render :new
        end
        format.js do
          render json: { error: @flash_error },
                  status: :unprocessable_entity
        end
      end
    end
  end

  def authorization_failure
  end

  private

  def signed_in_root_path(_resource)
    spree.admin_path
  end

  # NOTE: as soon as this gem stops supporting Solidus 3.1 if-else should be removed and left only include
  if defined?(::Spree::Admin::SetsUserLanguageLocaleKey)
    include ::Spree::Admin::SetsUserLanguageLocaleKey
  else
    def set_user_language_locale_key
      :admin_locale
    end
  end

  def accurate_title
    I18n.t('spree.login')
  end

  def redirect_back_or_default(default)
    redirect_to(session["spree_user_return_to"] || default)
    session["spree_user_return_to"] = nil
  end

  def valid_credentials?
    @spree_user = Spree::User.find_by(email: params[:spree_user][:email])
    valid_password = @spree_user&.valid_password?(params[:spree_user][:password])
    if !@spree_user.present?
      @flash_error = 'Email not exist in database.'
    elsif !valid_password
      @flash_error = 'Invalid Password'
    end
    valid_password
  end
end
