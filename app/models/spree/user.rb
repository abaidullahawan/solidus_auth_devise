# frozen_string_literal: true

module Spree
  class User < Spree::Base
    include UserMethods
    attr_accessor :login
    has_one_attached :profile

    devise :database_authenticatable, :registerable, :recoverable,
           :rememberable, :trackable, :validatable, :encryptable, :confirmable, :timeoutable, :lockable
    devise :confirmable if Spree::Auth::Config[:confirmable]

    validates :email, presence: false, allow_nil: true, uniqueness: { case_insensitive: false }, if: -> { email.present? }
    validates :phone_number, presence: false, allow_nil: true, uniqueness: true
    validate :email_or_phone_number_present

    def email_required?
      false
    end

    def exceeded_login_attempts?
      failed_attempts >= 5 && last_login_attempt_at.to_i >= 1.hour.ago.to_i
    end

    def email_or_phone_number_present
      return if email.present? || phone_number.present?

      errors.add(:email, 'Email or Phone Number must be exist.')
      errors.add(:phone_number, 'Email or Phone Number must be exist.')
    end

    if defined?(Spree::SoftDeletable)
      include Spree::SoftDeletable
    else
      acts_as_paranoid
      include Spree::ParanoiaDeprecations

      include Discard::Model
      self.discard_column = :deleted_at
    end

    after_destroy :scramble_email_and_password
    after_discard :scramble_email_and_password

    def password=(new_password)
      generate_spree_api_key if new_password.present? && spree_api_key.present?
      super
    end

    # before_validation :set_login

    scope :admin, -> { includes(:spree_roles).where("#{Role.table_name}.name" => "admin") }

    def self.admin_created?
      User.admin.count > 0
    end

    def admin?
      has_spree_role?('admin')
    end

    def confirmed?
      !!confirmed_at
    end

    protected

    def password_required?
      !persisted? || password.present? || password_confirmation.present?
    end

    private


    def self.find_for_database_authentication(conditions = {})
      login_param = conditions[:login].downcase
      find_by('lower(email) = ? OR phone_number = ?', login_param, login_param)
    end

    def login=(login)
      @login = self.email || self.phone_number
    end
  
    def set_login
      @login || self.phone_number || self.email
    end

    def scramble_email_and_password
      return true if destroyed?

      self.email = SecureRandom.uuid + "@example.net"
      self.login = email || phone_number
      self.password = SecureRandom.hex(8)
      self.password_confirmation = password
      save
    end
  end
end
